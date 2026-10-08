//go:build integration

// Run against a JetStream-enabled server:
//
//	docker run -d --rm --name nats-it -p 14222:4222 nats:2.11.9-alpine -js
//	NATS_TEST_URL=nats://127.0.0.1:14222 go test -tags integration ./pkg/nats/ -run Stream -v
package nats

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"reflect"
)

func must(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}

func testClient(t *testing.T) *NATSClient {
	url := os.Getenv("NATS_TEST_URL")
	if url == "" {
		t.Skip("NATS_TEST_URL not set")
	}
	c, err := NewNATSClient(NATSClientConfig{Enabled: true, URL: url, RetryOnFailedConnect: true})
	must(t, err, "connect")
	t.Cleanup(c.Close)
	return c
}

func TestStreamPublishConsume(t *testing.T) {
	c := testClient(t)
	opts := StreamOptions{Name: "IT_STREAM", Subjects: []string{"it.threats.>"}, Replicas: 1}
	must(t, c.EnsureStream(opts), "ensure")
	must(t, c.EnsureStream(opts), "ensure idempotent")
	opts.MaxAge = time.Hour
	must(t, c.EnsureStream(opts), "update existing")
	_ = c.js.PurgeStream("IT_STREAM")

	pub, err := c.NewStreamPublisher(StreamPublisherOptions{})
	must(t, err, "publisher")
	must(t, pub.Publish("it.threats.a", []byte("one"), "id-1"), "publish")
	must(t, pub.Publish("it.threats.a", []byte("one-dup"), "id-1"), "publish dup") // deduplicated
	must(t, pub.Publish("it.threats.b", []byte("poison"), "id-2"), "publish")
	must(t, pub.Publish("it.threats.b", []byte("two"), "id-3"), "publish")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	must(t, pub.Flush(ctx), "flush")

	sub, err := c.NewStreamSubscriber("IT_STREAM", "it-consumer", StreamSubscriberOptions{DeliverAll: true, FetchMaxWait: 200 * time.Millisecond})
	must(t, err, "subscriber")

	var mu sync.Mutex
	var got []string
	failedOnce := false
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- sub.Run(runCtx, func(_ context.Context, m *StreamMessage) error {
			mu.Lock()
			defer mu.Unlock()
			switch string(m.Data) {
			case "poison":
				return errors.Join(ErrDiscard, errors.New("bad payload"))
			case "two":
				if !failedOnce {
					failedOnce = true
					return errors.New("transient")
				}
			}
			got = append(got, string(m.Data))
			return nil
		})
	}()

	eventually(t, 8*time.Second, "two messages handled", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 2 })
	stop()
	<-done
	mu.Lock()
	if !reflect.DeepEqual(got, []string{"one", "two"}) {
		t.Errorf("got %v, want [one two] (duplicate dropped, poison discarded, transient failure redelivered)", got)
	}
	mu.Unlock()
}

func TestStreamPublisherRetriesUntilStreamExists(t *testing.T) {
	c := testClient(t)
	js, err := c.jetStream()
	must(t, err, "jetstream")
	_ = js.DeleteStream("IT_LATE")

	pub, err := c.NewStreamPublisher(StreamPublisherOptions{})
	must(t, err, "publisher")
	must(t, pub.Publish("it.late.x", []byte("early"), "late-1"), "publish") // no stream yet

	time.Sleep(300 * time.Millisecond)
	must(t, c.EnsureStream(StreamOptions{Name: "IT_LATE", Subjects: []string{"it.late.>"}, Replicas: 1}), "ensure late")

	eventually(t, 10*time.Second, "retry delivers once the stream exists", func() bool {
		info, err := js.StreamInfo("IT_LATE")
		return err == nil && info.State.Msgs == 1
	})
	retried, dropped := pub.Stats()
	if retried < 1 || dropped != 0 {
		t.Errorf("retried=%d dropped=%d, want retried>=1 dropped=0", retried, dropped)
	}
	_ = js.DeleteStream("IT_LATE")
	_ = js.DeleteStream("IT_STREAM")
}
