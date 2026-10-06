package k8shelld

import (
	"context"
	"sync"
	"testing"
	"time"

	sessionv1 "github.com/k8shell-io/common/pkg/api/gen/go/session/v1"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// fakeTcpipStream records sent frames. While gate is held, Send blocks,
// simulating a recording service that does not keep up.
type fakeTcpipStream struct {
	grpc.ClientStream
	gate   sync.RWMutex
	mu     sync.Mutex
	frames []*sessionv1.TcpipRecordingFrame
	closed bool
}

func (f *fakeTcpipStream) Send(fr *sessionv1.TcpipRecordingFrame) error {
	f.gate.RLock()
	defer f.gate.RUnlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames = append(f.frames, fr)
	return nil
}

func (f *fakeTcpipStream) CloseAndRecv() (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return &emptypb.Empty{}, nil
}

func (f *fakeTcpipStream) sent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.frames)
}

type fakeRecordingClient struct {
	sessionv1.RecordingServiceClient
	stream *fakeTcpipStream
}

func (c *fakeRecordingClient) StreamTcpipRecording(context.Context, ...grpc.CallOption) (
	grpc.ClientStreamingClient[sessionv1.TcpipRecordingFrame, emptypb.Empty], error) {
	return c.stream, nil
}

func newTestTcpipRecorder(t *testing.T, opts ...RecorderOption) (*Recorder, *fakeTcpipStream) {
	t.Helper()
	st := &fakeTcpipStream{}
	log := zerolog.Nop()
	r := NewTcpipRecorder(context.Background(), &fakeRecordingClient{stream: st},
		"pf-c11", "c1", "token", "127.0.0.1", 5000, "127.0.0.1", 8080, time.Now(), &log, opts...)
	return r, st
}

// totals sums sent data and reported drops per direction.
func totals(frames []*sessionv1.TcpipRecordingFrame) (data, dropped map[sessionv1.Direction]uint64) {
	data, dropped = map[sessionv1.Direction]uint64{}, map[sessionv1.Direction]uint64{}
	for _, f := range frames {
		if c := f.GetChunk(); c != nil {
			data[c.GetDirection()] += uint64(len(c.GetData()))
			dropped[c.GetDirection()] += c.GetDroppedBytes()
		}
	}
	return data, dropped
}

func TestRecorderSendsHeaderOptionsAndData(t *testing.T) {
	opts := &sessionv1.RecordingOptions{Format: sessionv1.RecordingFormat_RECORDING_FORMAT_PCAPNG}
	r, st := newTestTcpipRecorder(t, WithRecordingOptions(opts))
	r.ObserveInput([]byte("GET / HTTP/1.1\r\n\r\n"), time.Millisecond)
	r.Observe([]byte("HTTP/1.1 200 OK\r\n\r\n"), 2*time.Millisecond)
	r.Close()

	if !st.closed {
		t.Fatal("stream not closed")
	}
	if got := st.frames[0].GetHeader().GetOptions().GetFormat(); got != opts.Format {
		t.Fatalf("header options format = %v, want %v", got, opts.Format)
	}
	data, dropped := totals(st.frames)
	if data[sessionv1.Direction_DIRECTION_INPUT] != 18 || data[sessionv1.Direction_DIRECTION_OUTPUT] != 19 {
		t.Errorf("data = %v, want 18 input and 19 output bytes", data)
	}
	if dropped[sessionv1.Direction_DIRECTION_INPUT] != 0 || dropped[sessionv1.Direction_DIRECTION_OUTPUT] != 0 {
		t.Errorf("dropped = %v, want none", dropped)
	}
}

func TestRecorderDropsWhenBufferFullAndReportsGap(t *testing.T) {
	r, st := newTestTcpipRecorder(t, WithBufferBytes(100))

	// Wait for the header so the sender is in its loop, then stall it.
	for st.sent() == 0 {
		time.Sleep(time.Millisecond)
	}
	st.gate.Lock()

	chunk := make([]byte, 40)
	observed := map[sessionv1.Direction]uint64{}
	start := time.Now()
	for i := 0; i < 50; i++ {
		r.Observe(chunk, time.Duration(i)*time.Millisecond)
		r.ObserveInput(chunk[:10], time.Duration(i)*time.Millisecond)
		observed[sessionv1.Direction_DIRECTION_OUTPUT] += 40
		observed[sessionv1.Direction_DIRECTION_INPUT] += 10
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Observe blocked for %v while the stream was stalled", d)
	}

	st.gate.Unlock()
	// Data observed after the stall must carry the gap with it.
	r.Observe([]byte("after"), time.Second)
	r.Close()

	data, dropped := totals(st.frames)
	for dir, want := range observed {
		if dir == sessionv1.Direction_DIRECTION_OUTPUT {
			want += 5
		}
		if got := data[dir] + dropped[dir]; got != want {
			t.Errorf("%v: sent %d + dropped %d = %d, want %d", dir, data[dir], dropped[dir], got, want)
		}
		if dropped[dir] == 0 {
			t.Errorf("%v: no drops reported", dir)
		}
	}
}

func TestRecorderReportsTrailingGapOnClose(t *testing.T) {
	r, st := newTestTcpipRecorder(t, WithBufferBytes(10))
	for st.sent() == 0 {
		time.Sleep(time.Millisecond)
	}
	st.gate.Lock()
	r.Observe(make([]byte, 8), 0)  // fits
	r.Observe(make([]byte, 8), 0)  // dropped
	r.Observe(make([]byte, 30), 0) // dropped
	st.gate.Unlock()
	r.Close()

	data, dropped := totals(st.frames)
	out := sessionv1.Direction_DIRECTION_OUTPUT
	if data[out] != 8 || dropped[out] != 38 {
		t.Fatalf("sent %d dropped %d, want 8 and 38", data[out], dropped[out])
	}
	last := st.frames[len(st.frames)-1].GetChunk()
	if len(last.GetData()) != 0 || last.GetDroppedBytes() != 38 {
		t.Errorf("last chunk = %d data bytes, %d dropped; want a gap-only chunk of 38", len(last.GetData()), last.GetDroppedBytes())
	}
}

func TestRecorderIgnoresObserveAfterClose(t *testing.T) {
	r, st := newTestTcpipRecorder(t)
	r.Close()
	r.Observe([]byte("late"), 0) // must not panic or block
	if data, _ := totals(st.frames); data[sessionv1.Direction_DIRECTION_OUTPUT] != 0 {
		t.Errorf("data sent after close: %v", data)
	}
}
