//go:build integration

// Run against a JetStream-enabled server:
//
//	docker run -d --rm --name nats-it -p 14222:4222 nats:2.11.9-alpine -js
//	NATS_TEST_URL=nats://127.0.0.1:14222 go test -tags integration ./pkg/nats/ -run KV -v
package nats

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestSubscribeKVChanges(t *testing.T) {
	c := testClient(t)
	kv, err := c.NewKV(BucketOptions{Bucket: "it-kv-changes", BucketTTL: NoBucketTTL, Replicas: 1})
	must(t, err, "kv")

	var mu sync.Mutex
	var got []*KVEvent
	sub, err := c.SubscribeKVChanges("it-kv-changes", func(ev *KVEvent) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	must(t, err, "subscribe")
	defer sub.Unsubscribe()
	must(t, c.nc.Flush(), "flush")

	_, err = kv.Set("alice", []byte(`{"locked":true}`))
	must(t, err, "set")
	must(t, kv.Delete("alice"), "delete")

	eventually(t, 5*time.Second, "put and delete delivered", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 2
	})
	if got[0].Key != "alice" || string(got[0].Value) != `{"locked":true}` {
		t.Fatalf("put event = %+v", got[0])
	}
	if got[1].Key != "alice" || len(got[1].Value) != 0 || got[1].Op != "DEL" {
		t.Fatalf("delete event = %+v", got[1])
	}

	js, _ := c.jetStream()
	info, err := js.StreamInfo("KV_it-kv-changes")
	must(t, err, "stream info")
	if info.State.Consumers != 0 {
		t.Fatalf("consumers = %d, want 0", info.State.Consumers)
	}
}

func TestKVSubscriberDeletesConsumerOnCancel(t *testing.T) {
	c := testClient(t)
	_, err := c.NewKV(BucketOptions{Bucket: "it-kv-sub", BucketTTL: NoBucketTTL, Replicas: 1})
	must(t, err, "kv")

	sub, err := c.NewKVSubscriber("it-kv-sub", "it-durable", KVSubscriberOptions{FetchMaxWait: 30 * time.Second})
	must(t, err, "subscriber")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sub.StartPull(ctx, func(context.Context, *KVEvent) error { return nil }) }()

	js, _ := c.jetStream()
	eventually(t, 5*time.Second, "consumer created", func() bool {
		_, err := js.ConsumerInfo("KV_it-kv-sub", "it-durable")
		return err == nil
	})

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartPull did not return promptly after cancel")
	}
	if _, err := js.ConsumerInfo("KV_it-kv-sub", "it-durable"); !errors.Is(err, nats.ErrConsumerNotFound) {
		t.Fatalf("consumer still present after cancel: %v", err)
	}
}
