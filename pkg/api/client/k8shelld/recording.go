// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package k8shelld

import (
	"context"
	"io"
	"time"

	sessionv1 "github.com/k8shell-io/common/pkg/api/gen/go/session/v1"
	"github.com/rs/zerolog"
)

const (
	recorderFrameChanSize = 512
	recorderFlushInterval = 50 * time.Millisecond
	recorderMaxBatchBytes = 32 * 1024
)

type recorderFrame struct {
	data   []byte
	offset int64 // milliseconds since session start
	resize *recorderResizeEvent
}

type recorderResizeEvent struct {
	width  uint32
	height uint32
}

// Recorder owns a single gRPC client-streaming session to the recording service.
// All exported methods are safe to call from multiple goroutines.
// A nil Recorder is safe to use — all methods are no-ops.
type Recorder struct {
	ch   chan recorderFrame
	done chan struct{}
	log  *zerolog.Logger
}

// NewRecorder opens a streaming session to the recording service and starts a
// background sender goroutine. The RecordingHeader is sent as the first frame.
// Returns nil when client is nil (recording disabled), which all methods treat
// as a no-op.
func NewRecorder(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, username string,
	streamType sessionv1.StreamType,
	width, height uint32,
	startedAt time.Time,
	log *zerolog.Logger,
) *Recorder {
	if client == nil {
		return nil
	}

	r := &Recorder{
		ch:   make(chan recorderFrame, recorderFrameChanSize),
		done: make(chan struct{}),
		log:  log,
	}

	go r.run(ctx, client, sessionID, username, streamType, width, height, startedAt)
	return r
}

// Observe enqueues a terminal output frame. Non-blocking; frames are dropped
// if the internal channel is full to protect the SSH session goroutine.
func (r *Recorder) Observe(data []byte, offset time.Duration) {
	if r == nil || len(data) == 0 {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case r.ch <- recorderFrame{data: cp, offset: offset.Milliseconds()}:
	default:
		// channel full — drop frame, never block the session
	}
}

// ObserveResize enqueues a terminal resize frame. Non-blocking.
func (r *Recorder) ObserveResize(width, height uint32, offset time.Duration) {
	if r == nil {
		return
	}
	select {
	case r.ch <- recorderFrame{
		offset: offset.Milliseconds(),
		resize: &recorderResizeEvent{width: width, height: height},
	}:
	default:
	}
}

// Close signals the sender goroutine to drain any buffered frames and close
// the gRPC stream. Blocks until the stream is fully closed.
func (r *Recorder) Close() {
	if r == nil {
		return
	}
	close(r.ch)
	<-r.done
}

// *** RecordingAdapter

// RecordingAdapter wraps a BufferedReadWriter and intercepts Write calls to
// forward terminal output bytes to a recording observer function.
// The observer is called synchronously but is expected to be non-blocking
// (e.g. a channel send with a select/default).
type RecordingAdapter struct {
	BufferedReadWriter
	observe func(data []byte, offset time.Duration)
	start   time.Time
}

// NewRecordingAdapter wraps rw, forwarding all written bytes to observe.
// start is the wall-clock session start time used to compute offsets.
func NewRecordingAdapter(rw BufferedReadWriter, start time.Time, observe func([]byte, time.Duration)) *RecordingAdapter {
	return &RecordingAdapter{
		BufferedReadWriter: rw,
		observe:            observe,
		start:              start,
	}
}

// Write intercepts output bytes before forwarding to the underlying writer.
func (a *RecordingAdapter) Write(p []byte) (int, error) {
	n, err := a.BufferedReadWriter.Write(p)
	if n > 0 {
		a.observe(p[:n], time.Since(a.start))
	}
	return n, err
}

// Stderr returns a writer that also intercepts output through the observer.
func (a *RecordingAdapter) Stderr() io.Writer {
	return &recordingWriter{
		Writer:  a.BufferedReadWriter.Stderr(),
		observe: a.observe,
		start:   a.start,
	}
}

type recordingWriter struct {
	io.Writer
	observe func(data []byte, offset time.Duration)
	start   time.Time
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.observe(p[:n], time.Since(w.start))
	}
	return n, err
}

func (r *Recorder) run(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, username string,
	streamType sessionv1.StreamType,
	width, height uint32,
	startedAt time.Time,
) {
	defer close(r.done)

	stream, err := client.StreamRecording(ctx)
	if err != nil {
		r.log.Warn().Msgf("Failed to open recording stream for session %s: %v", sessionID, err)
		for range r.ch {
		}
		return
	}

	if err = stream.Send(&sessionv1.RecordingFrame{
		Payload: &sessionv1.RecordingFrame_Header{
			Header: &sessionv1.RecordingHeader{
				SessionId:  sessionID,
				Username:   username,
				StartedAt:  startedAt.Unix(),
				StreamType: streamType,
				Width:      width,
				Height:     height,
			},
		},
	}); err != nil {
		r.log.Warn().Msgf("Failed to send recording header for session %s: %v", sessionID, err)
		for range r.ch {
		}
		return
	}

	ticker := time.NewTicker(recorderFlushInterval)
	defer ticker.Stop()

	var (
		batchData   []byte
		batchOffset int64
		batchLen    int
	)

	flush := func() {
		if batchLen == 0 {
			return
		}
		if sendErr := stream.Send(&sessionv1.RecordingFrame{
			Payload: &sessionv1.RecordingFrame_Chunk{
				Chunk: &sessionv1.DataChunk{
					TimeOffsetMs: batchOffset,
					Data:         batchData,
					Direction:    sessionv1.Direction_DIRECTION_OUTPUT,
				},
			},
		}); sendErr != nil {
			r.log.Debug().Msgf("Failed to send recording chunk for session %s: %v", sessionID, sendErr)
		}
		batchData = nil
		batchLen = 0
	}

	for {
		select {
		case frame, ok := <-r.ch:
			if !ok {
				flush()
				if _, closeErr := stream.CloseAndRecv(); closeErr != nil {
					r.log.Debug().Msgf("Recording stream closed for session %s: %v", sessionID, closeErr)
				}
				return
			}

			if frame.resize != nil {
				flush()
				if sendErr := stream.Send(&sessionv1.RecordingFrame{
					Payload: &sessionv1.RecordingFrame_Resize{
						Resize: &sessionv1.TerminalResize{
							TimeOffsetMs: frame.offset,
							Width:        frame.resize.width,
							Height:       frame.resize.height,
						},
					},
				}); sendErr != nil {
					r.log.Debug().Msgf("Failed to send resize frame for session %s: %v", sessionID, sendErr)
				}
				continue
			}

			if batchLen == 0 {
				batchOffset = frame.offset
			}
			batchData = append(batchData, frame.data...)
			batchLen += len(frame.data)
			if batchLen >= recorderMaxBatchBytes {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}
