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
	data      []byte
	offset    int64 // milliseconds since session start
	direction sessionv1.Direction
	resize    *recorderResizeEvent
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

// NewShellRecorder opens a shell-channel streaming session to the recording service
// and starts a background sender goroutine. The ShellRecordingHeader is sent as the
// first frame. Returns nil when client is nil (recording disabled), which all methods
// treat as a no-op.
func NewShellRecorder(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, username string,
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
	go r.runShell(ctx, client, sessionID, username, width, height, startedAt)
	return r
}

// NewExecRecorder opens an exec-channel streaming session to the recording service
// and starts a background sender goroutine. The ExecRecordingHeader is sent as the
// first frame. Returns nil when client is nil.
func NewExecRecorder(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, username, command string,
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
	go r.runExec(ctx, client, sessionID, username, command, startedAt)
	return r
}

// NewTcpipRecorder opens a TCP/IP-channel streaming session to the recording service
// and starts a background sender goroutine. The TcpipRecordingHeader is sent as the
// first frame. Returns nil when client is nil.
func NewTcpipRecorder(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, username string,
	srcHost string, srcPort uint32,
	dstHost string, dstPort uint32,
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
	go r.runTcpip(ctx, client, sessionID, username, srcHost, srcPort, dstHost, dstPort, startedAt)
	return r
}

// Observe enqueues an output (service→client) frame. Non-blocking; frames are dropped
// if the internal channel is full to protect the SSH session goroutine.
func (r *Recorder) Observe(data []byte, offset time.Duration) {
	if r == nil || len(data) == 0 {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case r.ch <- recorderFrame{data: cp, offset: offset.Milliseconds(), direction: sessionv1.Direction_DIRECTION_OUTPUT}:
	default:
		// channel full — drop frame, never block the session
	}
}

// ObserveInput enqueues an input (client→service) frame. Non-blocking.
func (r *Recorder) ObserveInput(data []byte, offset time.Duration) {
	if r == nil || len(data) == 0 {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case r.ch <- recorderFrame{data: cp, offset: offset.Milliseconds(), direction: sessionv1.Direction_DIRECTION_INPUT}:
	default:
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

// RecordingAdapter wraps a BufferedReadWriter and intercepts Write (and optionally Read)
// calls to forward bytes to recording observer functions.
// Both observers are called synchronously but must be non-blocking.
type RecordingAdapter struct {
	BufferedReadWriter
	observeWrite func(data []byte, offset time.Duration)
	observeRead  func(data []byte, offset time.Duration) // nil for output-only recording
	start        time.Time
}

// NewRecordingAdapter wraps rw, forwarding written bytes to observe.
// start is the wall-clock session start time used to compute offsets.
func NewRecordingAdapter(rw BufferedReadWriter, start time.Time, observe func([]byte, time.Duration)) *RecordingAdapter {
	return &RecordingAdapter{
		BufferedReadWriter: rw,
		observeWrite:       observe,
		start:              start,
	}
}

// NewBidirectionalRecordingAdapter wraps rw, forwarding written bytes to observeWrite
// and read bytes to observeRead, capturing both traffic directions.
func NewBidirectionalRecordingAdapter(
	rw BufferedReadWriter,
	start time.Time,
	observeWrite func([]byte, time.Duration),
	observeRead func([]byte, time.Duration),
) *RecordingAdapter {
	return &RecordingAdapter{
		BufferedReadWriter: rw,
		observeWrite:       observeWrite,
		observeRead:        observeRead,
		start:              start,
	}
}

// Write intercepts output (service→client) bytes before forwarding to the underlying writer.
func (a *RecordingAdapter) Write(p []byte) (int, error) {
	n, err := a.BufferedReadWriter.Write(p)
	if n > 0 && a.observeWrite != nil {
		a.observeWrite(p[:n], time.Since(a.start))
	}
	return n, err
}

// Read intercepts input (client→service) bytes after reading from the underlying reader.
func (a *RecordingAdapter) Read(p []byte) (int, error) {
	n, err := a.BufferedReadWriter.Read(p)
	if n > 0 && a.observeRead != nil {
		a.observeRead(p[:n], time.Since(a.start))
	}
	return n, err
}

// Stderr returns a writer that also intercepts output through the write observer.
func (a *RecordingAdapter) Stderr() io.Writer {
	return &recordingWriter{
		Writer:  a.BufferedReadWriter.Stderr(),
		observe: a.observeWrite,
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

func (r *Recorder) runShell(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, username string,
	width, height uint32,
	startedAt time.Time,
) {
	defer close(r.done)

	stream, err := client.StreamShellRecording(ctx)
	if err != nil {
		r.log.Warn().Msgf("Failed to open shell recording stream for session %s: %v", sessionID, err)
		for range r.ch {
		}
		return
	}

	if err = stream.Send(&sessionv1.ShellRecordingFrame{
		Payload: &sessionv1.ShellRecordingFrame_Header{
			Header: &sessionv1.ShellRecordingHeader{
				SessionId: sessionID,
				Username:  username,
				StartedAt: startedAt.Unix(),
				Width:     width,
				Height:    height,
			},
		},
	}); err != nil {
		r.log.Warn().Msgf("Failed to send shell recording header for session %s: %v", sessionID, err)
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
		if sendErr := stream.Send(&sessionv1.ShellRecordingFrame{
			Payload: &sessionv1.ShellRecordingFrame_Chunk{
				Chunk: &sessionv1.DataChunk{
					TimeOffsetMs: batchOffset,
					Data:         batchData,
					Direction:    sessionv1.Direction_DIRECTION_OUTPUT,
				},
			},
		}); sendErr != nil {
			r.log.Debug().Msgf("Failed to send shell recording chunk for session %s: %v", sessionID, sendErr)
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
					r.log.Debug().Msgf("Shell recording stream closed for session %s: %v", sessionID, closeErr)
				}
				return
			}

			if frame.resize != nil {
				flush()
				if sendErr := stream.Send(&sessionv1.ShellRecordingFrame{
					Payload: &sessionv1.ShellRecordingFrame_Resize{
						Resize: &sessionv1.TerminalResize{
							TimeOffsetMs: frame.offset,
							Width:        frame.resize.width,
							Height:       frame.resize.height,
						},
					},
				}); sendErr != nil {
					r.log.Debug().Msgf("Failed to send shell resize frame for session %s: %v", sessionID, sendErr)
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

func (r *Recorder) runExec(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, username, command string,
	startedAt time.Time,
) {
	defer close(r.done)

	stream, err := client.StreamExecRecording(ctx)
	if err != nil {
		r.log.Warn().Msgf("Failed to open exec recording stream for session %s: %v", sessionID, err)
		for range r.ch {
		}
		return
	}

	if err = stream.Send(&sessionv1.ExecRecordingFrame{
		Payload: &sessionv1.ExecRecordingFrame_Header{
			Header: &sessionv1.ExecRecordingHeader{
				SessionId: sessionID,
				Username:  username,
				StartedAt: startedAt.Unix(),
				Command:   command,
			},
		},
	}); err != nil {
		r.log.Warn().Msgf("Failed to send exec recording header for session %s: %v", sessionID, err)
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
		if sendErr := stream.Send(&sessionv1.ExecRecordingFrame{
			Payload: &sessionv1.ExecRecordingFrame_Chunk{
				Chunk: &sessionv1.DataChunk{
					TimeOffsetMs: batchOffset,
					Data:         batchData,
					Direction:    sessionv1.Direction_DIRECTION_OUTPUT,
				},
			},
		}); sendErr != nil {
			r.log.Debug().Msgf("Failed to send exec recording chunk for session %s: %v", sessionID, sendErr)
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
					r.log.Debug().Msgf("Exec recording stream closed for session %s: %v", sessionID, closeErr)
				}
				return
			}

			// exec channels don't have resize events; discard
			if frame.resize != nil {
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

func (r *Recorder) runTcpip(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, username string,
	srcHost string, srcPort uint32,
	dstHost string, dstPort uint32,
	startedAt time.Time,
) {
	defer close(r.done)

	stream, err := client.StreamTcpipRecording(ctx)
	if err != nil {
		r.log.Warn().Msgf("Failed to open tcpip recording stream for session %s: %v", sessionID, err)
		for range r.ch {
		}
		return
	}

	if err = stream.Send(&sessionv1.TcpipRecordingFrame{
		Payload: &sessionv1.TcpipRecordingFrame_Header{
			Header: &sessionv1.TcpipRecordingHeader{
				SessionId: sessionID,
				Username:  username,
				StartedAt: startedAt.Unix(),
				SrcHost:   srcHost,
				SrcPort:   srcPort,
				DstHost:   dstHost,
				DstPort:   dstPort,
			},
		},
	}); err != nil {
		r.log.Warn().Msgf("Failed to send tcpip recording header for session %s: %v", sessionID, err)
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
		batchDir    sessionv1.Direction
	)

	flush := func() {
		if batchLen == 0 {
			return
		}
		if sendErr := stream.Send(&sessionv1.TcpipRecordingFrame{
			Payload: &sessionv1.TcpipRecordingFrame_Chunk{
				Chunk: &sessionv1.DataChunk{
					TimeOffsetMs: batchOffset,
					Data:         batchData,
					Direction:    batchDir,
				},
			},
		}); sendErr != nil {
			r.log.Debug().Msgf("Failed to send tcpip recording chunk for session %s: %v", sessionID, sendErr)
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
					r.log.Debug().Msgf("Tcpip recording stream closed for session %s: %v", sessionID, closeErr)
				}
				return
			}

			// TCP/IP channels don't have resize events; discard
			if frame.resize != nil {
				continue
			}

			// Flush before switching direction so chunks are never mixed.
			if batchLen > 0 && frame.direction != batchDir {
				flush()
			}
			if batchLen == 0 {
				batchOffset = frame.offset
				batchDir = frame.direction
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
