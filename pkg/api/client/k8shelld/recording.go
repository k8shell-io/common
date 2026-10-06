// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package k8shelld

import (
	"context"
	"io"
	"sync"
	"time"

	sessionv1 "github.com/k8shell-io/common/pkg/api/gen/go/session/v1"
	"github.com/rs/zerolog"
)

const (
	// DefaultRecorderBufferBytes is the default limit on data a Recorder
	// queues while it waits to send it to the recording service.
	DefaultRecorderBufferBytes = 8 << 20

	recorderFlushInterval = 50 * time.Millisecond
	recorderMaxBatchBytes = 32 * 1024
)

type recorderFrame struct {
	data      []byte
	offset    int64 // milliseconds since session start
	direction sessionv1.Direction
	dropped   uint64 // bytes of direction dropped right before this frame
	resize    *recorderResizeEvent
}

type recorderResizeEvent struct {
	width  uint32
	height uint32
}

// RecorderOption configures a Recorder.
type RecorderOption func(*recorderSettings)

type recorderSettings struct {
	options     *sessionv1.RecordingOptions
	bufferBytes int
}

// WithRecordingOptions sets the recording setup sent in the stream header
// (format, gzip, VS Code terminals). Without it the session service applies
// its configured defaults.
func WithRecordingOptions(o *sessionv1.RecordingOptions) RecorderOption {
	return func(s *recorderSettings) { s.options = o }
}

// WithBufferBytes limits the data the Recorder queues while it waits to send
// it. Data observed beyond the limit is dropped and reported to the recording
// service as a gap. n <= 0 selects DefaultRecorderBufferBytes.
func WithBufferBytes(n int) RecorderOption {
	return func(s *recorderSettings) { s.bufferBytes = n }
}

func applyRecorderOptions(opts []RecorderOption) recorderSettings {
	var s recorderSettings
	for _, o := range opts {
		o(&s)
	}
	if s.bufferBytes <= 0 {
		s.bufferBytes = DefaultRecorderBufferBytes
	}
	return s
}

// Recorder owns a single gRPC client-streaming session to the recording service.
// All exported methods are safe to call from multiple goroutines and never
// block on the recording service: when the send queue is full, observed data
// is dropped and the number of dropped bytes is sent with the next chunk of
// the same direction.
// A nil Recorder is safe to use — all methods are no-ops.
type Recorder struct {
	mu        sync.Mutex
	queue     []recorderFrame
	queued    int       // data bytes queued or being sent
	maxBytes  int       // limit on queued
	dropped   [2]uint64 // per direction, not yet reported
	dropTotal uint64
	closed    bool
	notify    chan struct{} // capacity 1; signals new frames or close
	done      chan struct{}
	options   *sessionv1.RecordingOptions
	log       *zerolog.Logger
}

func newRecorder(log *zerolog.Logger, opts []RecorderOption) *Recorder {
	s := applyRecorderOptions(opts)
	return &Recorder{
		maxBytes: s.bufferBytes,
		options:  s.options,
		notify:   make(chan struct{}, 1),
		done:     make(chan struct{}),
		log:      log,
	}
}

// NewShellRecorder opens a shell-channel streaming session to the recording service
// and starts a background sender goroutine. The ShellRecordingHeader is sent as the
// first frame. Returns nil when client is nil (recording disabled), which all methods
// treat as a no-op.
func NewShellRecorder(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, connectionID, userToken string,
	width, height uint32,
	startedAt time.Time,
	log *zerolog.Logger,
	opts ...RecorderOption,
) *Recorder {
	if client == nil {
		return nil
	}
	r := newRecorder(log, opts)
	go r.runShell(ctx, client, sessionID, connectionID, userToken, width, height, startedAt)
	return r
}

// NewExecRecorder opens an exec-channel streaming session to the recording service
// and starts a background sender goroutine. The ExecRecordingHeader is sent as the
// first frame. Returns nil when client is nil.
func NewExecRecorder(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, connectionID, userToken, command string,
	startedAt time.Time,
	log *zerolog.Logger,
	opts ...RecorderOption,
) *Recorder {
	if client == nil {
		return nil
	}
	r := newRecorder(log, opts)
	go r.runExec(ctx, client, sessionID, connectionID, userToken, command, startedAt)
	return r
}

// NewSftpRecorder opens an SFTP-channel streaming session to the recording service
// and starts a background sender goroutine. The SftpRecordingHeader is sent as the
// first frame. Returns nil when client is nil.
func NewSftpRecorder(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, connectionID, userToken string,
	startedAt time.Time,
	log *zerolog.Logger,
	opts ...RecorderOption,
) *Recorder {
	if client == nil {
		return nil
	}
	r := newRecorder(log, opts)
	go r.runSftp(ctx, client, sessionID, connectionID, userToken, startedAt)
	return r
}

// NewTcpipRecorder opens a TCP/IP-channel streaming session to the recording service
// and starts a background sender goroutine. The TcpipRecordingHeader is sent as the
// first frame. Returns nil when client is nil.
func NewTcpipRecorder(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, connectionID, userToken string,
	srcHost string, srcPort uint32,
	dstHost string, dstPort uint32,
	startedAt time.Time,
	log *zerolog.Logger,
	opts ...RecorderOption,
) *Recorder {
	if client == nil {
		return nil
	}
	r := newRecorder(log, opts)
	go r.runTcpip(ctx, client, sessionID, connectionID, userToken, srcHost, srcPort, dstHost, dstPort, startedAt)
	return r
}

// directionIndex maps a direction to its index in Recorder.dropped.
func directionIndex(d sessionv1.Direction) int {
	if d == sessionv1.Direction_DIRECTION_INPUT {
		return 1
	}
	return 0
}

// enqueue adds frame to the send queue without blocking. A data frame that
// does not fit in the buffer is dropped and counted; the count is attached to
// the next queued frame of the same direction.
func (r *Recorder) enqueue(frame recorderFrame) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	n := len(frame.data)
	if n > 0 {
		d := directionIndex(frame.direction)
		if r.queued+n > r.maxBytes {
			r.dropped[d] += uint64(n)
			r.dropTotal += uint64(n)
			return
		}
		frame.dropped = r.dropped[d]
		r.dropped[d] = 0
		r.queued += n
	}
	r.queue = append(r.queue, frame)
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// take removes and returns the queued frames. Their bytes stay counted
// against the buffer until release, so frames being sent still use it.
func (r *Recorder) take() (frames []recorderFrame, closed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	frames, r.queue = r.queue, nil
	return frames, r.closed
}

// release returns n bytes of sent data to the buffer.
func (r *Recorder) release(n int) {
	r.mu.Lock()
	r.queued -= n
	r.mu.Unlock()
}

// abandon stops accepting frames after the stream could not be opened.
func (r *Recorder) abandon() {
	r.mu.Lock()
	r.closed = true
	r.queue = nil
	r.mu.Unlock()
}

// Observe enqueues an output (service→client) frame. Non-blocking; frames are dropped
// if the send buffer is full to protect the SSH session goroutine.
func (r *Recorder) Observe(data []byte, offset time.Duration) {
	if r == nil || len(data) == 0 {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	r.enqueue(recorderFrame{data: cp, offset: offset.Milliseconds(), direction: sessionv1.Direction_DIRECTION_OUTPUT})
}

// ObserveInput enqueues an input (client→service) frame. Non-blocking.
func (r *Recorder) ObserveInput(data []byte, offset time.Duration) {
	if r == nil || len(data) == 0 {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	r.enqueue(recorderFrame{data: cp, offset: offset.Milliseconds(), direction: sessionv1.Direction_DIRECTION_INPUT})
}

// ObserveResize enqueues a terminal resize frame. Non-blocking.
func (r *Recorder) ObserveResize(width, height uint32, offset time.Duration) {
	if r == nil {
		return
	}
	r.enqueue(recorderFrame{
		offset: offset.Milliseconds(),
		resize: &recorderResizeEvent{width: width, height: height},
	})
}

// Close signals the sender goroutine to send any queued frames and close
// the gRPC stream. Blocks until the stream is fully closed.
func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
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

// *** Sender

// recordingSink sends the frames of one recording stream type.
type recordingSink struct {
	kind string // stream type for log messages
	// sendChunk sends a data chunk.
	sendChunk func(*sessionv1.DataChunk) error
	// sendResize sends a resize event; nil discards resize frames.
	sendResize func(*sessionv1.TerminalResize) error
	// splitDirection keeps input and output in separate chunks. When false,
	// every chunk is sent as output.
	splitDirection bool
	// closeAndRecv closes the stream.
	closeAndRecv func() error
}

// run sends queued frames to sink in batches of up to recorderMaxBatchBytes,
// flushed every recorderFlushInterval, until the Recorder is closed.
func (r *Recorder) run(sessionID string, sink recordingSink) {
	ticker := time.NewTicker(recorderFlushInterval)
	defer ticker.Stop()

	var (
		batchData    []byte
		batchOffset  int64
		batchDir     sessionv1.Direction
		batchDropped uint64
		lastOffset   int64
	)

	send := func(chunk *sessionv1.DataChunk) {
		if err := sink.sendChunk(chunk); err != nil {
			r.log.Debug().Msgf("Failed to send %s recording chunk for session %s: %v", sink.kind, sessionID, err)
		}
	}
	flush := func() {
		if len(batchData) == 0 {
			return
		}
		send(&sessionv1.DataChunk{
			TimeOffsetMs: batchOffset,
			Data:         batchData,
			Direction:    batchDir,
			DroppedBytes: batchDropped,
		})
		batchData = nil
		batchDropped = 0
	}
	add := func(f recorderFrame) {
		dir := f.direction
		if !sink.splitDirection {
			dir = sessionv1.Direction_DIRECTION_OUTPUT
		}
		// A gap starts a new chunk so it is reported where it happened.
		if len(batchData) > 0 && (dir != batchDir || f.dropped > 0) {
			flush()
		}
		if len(batchData) == 0 {
			batchOffset = f.offset
			batchDir = dir
		}
		batchDropped += f.dropped
		batchData = append(batchData, f.data...)
		lastOffset = f.offset
		if len(batchData) >= recorderMaxBatchBytes {
			flush()
		}
	}

	for {
		select {
		case <-r.notify:
		case <-ticker.C:
			flush()
			continue
		}

		frames, closed := r.take()
		n := 0
		for _, f := range frames {
			if f.resize != nil {
				if sink.sendResize == nil {
					continue
				}
				flush()
				if err := sink.sendResize(&sessionv1.TerminalResize{
					TimeOffsetMs: f.offset,
					Width:        f.resize.width,
					Height:       f.resize.height,
				}); err != nil {
					r.log.Debug().Msgf("Failed to send %s resize frame for session %s: %v", sink.kind, sessionID, err)
				}
				continue
			}
			add(f)
			n += len(f.data)
		}
		r.release(n)
		if !closed {
			continue
		}

		flush()
		r.sendTrailingGaps(sessionID, sink, lastOffset, send)
		if err := sink.closeAndRecv(); err != nil {
			r.log.Debug().Msgf("%s recording stream closed for session %s: %v", sink.kind, sessionID, err)
		}
		return
	}
}

// sendTrailingGaps reports bytes dropped after the last sent chunk, and logs
// the stream's total drops.
func (r *Recorder) sendTrailingGaps(sessionID string, sink recordingSink, offset int64, send func(*sessionv1.DataChunk)) {
	r.mu.Lock()
	dropped, total := r.dropped, r.dropTotal
	r.dropped = [2]uint64{}
	r.mu.Unlock()

	for i, dir := range []sessionv1.Direction{sessionv1.Direction_DIRECTION_OUTPUT, sessionv1.Direction_DIRECTION_INPUT} {
		if dropped[i] == 0 {
			continue
		}
		if !sink.splitDirection {
			dir = sessionv1.Direction_DIRECTION_OUTPUT
		}
		send(&sessionv1.DataChunk{TimeOffsetMs: offset, Direction: dir, DroppedBytes: dropped[i]})
	}
	if total > 0 {
		r.log.Warn().Msgf("%s recording for session %s dropped %d bytes: send buffer of %d bytes was full",
			sink.kind, sessionID, total, r.maxBytes)
	}
}

// openFailed logs a stream that could not be opened and stops accepting frames.
func (r *Recorder) openFailed(kind, what, sessionID string, err error) {
	r.log.Warn().Msgf("Failed to %s %s recording stream for session %s: %v", what, kind, sessionID, err)
	r.abandon()
}

func (r *Recorder) runShell(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, connectionID, userToken string,
	width, height uint32,
	startedAt time.Time,
) {
	defer close(r.done)

	stream, err := client.StreamShellRecording(ctx)
	if err != nil {
		r.openFailed("shell", "open", sessionID, err)
		return
	}
	if err = stream.Send(&sessionv1.ShellRecordingFrame{
		Payload: &sessionv1.ShellRecordingFrame_Header{
			Header: &sessionv1.ShellRecordingHeader{
				SessionId:    sessionID,
				ConnectionId: connectionID,
				UserToken:    userToken,
				StartedAt:    startedAt.Unix(),
				Width:        width,
				Height:       height,
				Options:      r.options,
			},
		},
	}); err != nil {
		r.openFailed("shell", "send header of", sessionID, err)
		return
	}

	r.run(sessionID, recordingSink{
		kind: "shell",
		sendChunk: func(c *sessionv1.DataChunk) error {
			return stream.Send(&sessionv1.ShellRecordingFrame{Payload: &sessionv1.ShellRecordingFrame_Chunk{Chunk: c}})
		},
		sendResize: func(rs *sessionv1.TerminalResize) error {
			return stream.Send(&sessionv1.ShellRecordingFrame{Payload: &sessionv1.ShellRecordingFrame_Resize{Resize: rs}})
		},
		closeAndRecv: func() error { _, err := stream.CloseAndRecv(); return err },
	})
}

func (r *Recorder) runExec(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, connectionID, userToken, command string,
	startedAt time.Time,
) {
	defer close(r.done)

	stream, err := client.StreamExecRecording(ctx)
	if err != nil {
		r.openFailed("exec", "open", sessionID, err)
		return
	}
	if err = stream.Send(&sessionv1.ExecRecordingFrame{
		Payload: &sessionv1.ExecRecordingFrame_Header{
			Header: &sessionv1.ExecRecordingHeader{
				SessionId:    sessionID,
				ConnectionId: connectionID,
				UserToken:    userToken,
				StartedAt:    startedAt.Unix(),
				Command:      command,
				Options:      r.options,
			},
		},
	}); err != nil {
		r.openFailed("exec", "send header of", sessionID, err)
		return
	}

	r.run(sessionID, recordingSink{
		kind: "exec",
		sendChunk: func(c *sessionv1.DataChunk) error {
			return stream.Send(&sessionv1.ExecRecordingFrame{Payload: &sessionv1.ExecRecordingFrame_Chunk{Chunk: c}})
		},
		closeAndRecv: func() error { _, err := stream.CloseAndRecv(); return err },
	})
}

func (r *Recorder) runSftp(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, connectionID, userToken string,
	startedAt time.Time,
) {
	defer close(r.done)

	stream, err := client.StreamSftpRecording(ctx)
	if err != nil {
		r.openFailed("sftp", "open", sessionID, err)
		return
	}
	if err = stream.Send(&sessionv1.SftpRecordingFrame{
		Payload: &sessionv1.SftpRecordingFrame_Header{
			Header: &sessionv1.SftpRecordingHeader{
				SessionId:    sessionID,
				ConnectionId: connectionID,
				UserToken:    userToken,
				StartedAt:    startedAt.Unix(),
				Options:      r.options,
			},
		},
	}); err != nil {
		r.openFailed("sftp", "send header of", sessionID, err)
		return
	}

	r.run(sessionID, recordingSink{
		kind: "sftp",
		sendChunk: func(c *sessionv1.DataChunk) error {
			return stream.Send(&sessionv1.SftpRecordingFrame{Payload: &sessionv1.SftpRecordingFrame_Chunk{Chunk: c}})
		},
		splitDirection: true,
		closeAndRecv:   func() error { _, err := stream.CloseAndRecv(); return err },
	})
}

func (r *Recorder) runTcpip(
	ctx context.Context,
	client sessionv1.RecordingServiceClient,
	sessionID, connectionID, userToken string,
	srcHost string, srcPort uint32,
	dstHost string, dstPort uint32,
	startedAt time.Time,
) {
	defer close(r.done)

	stream, err := client.StreamTcpipRecording(ctx)
	if err != nil {
		r.openFailed("tcpip", "open", sessionID, err)
		return
	}
	if err = stream.Send(&sessionv1.TcpipRecordingFrame{
		Payload: &sessionv1.TcpipRecordingFrame_Header{
			Header: &sessionv1.TcpipRecordingHeader{
				SessionId:    sessionID,
				ConnectionId: connectionID,
				UserToken:    userToken,
				StartedAt:    startedAt.Unix(),
				SrcHost:      srcHost,
				SrcPort:      srcPort,
				DstHost:      dstHost,
				DstPort:      dstPort,
				Options:      r.options,
			},
		},
	}); err != nil {
		r.openFailed("tcpip", "send header of", sessionID, err)
		return
	}

	r.run(sessionID, recordingSink{
		kind: "tcpip",
		sendChunk: func(c *sessionv1.DataChunk) error {
			return stream.Send(&sessionv1.TcpipRecordingFrame{Payload: &sessionv1.TcpipRecordingFrame_Chunk{Chunk: c}})
		},
		splitDirection: true,
		closeAndRecv:   func() error { _, err := stream.CloseAndRecv(); return err },
	})
}
