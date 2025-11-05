package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/nats-io/nats.go"
)

// KVEvent represents a single key-value event.
type KVEvent struct {
	Bucket string
	Key    string
	Op     string
	Value  []byte
	Seq    uint64
	Time   time.Time
	Msg    *nats.Msg
}

// KVSubscriberOptions holds options for the KVSubscriber.
type KVSubscriberOptions struct {
	DeliverAll     bool // true to replay all from start; false to get new only
	AckWait        time.Duration
	MaxAckPending  int
	FetchBatchSize int
	FetchMaxWait   time.Duration
}

// KVSubscriber is a NATS JetStream KV bucket subscriber.
type KVSubscriber struct {
	nc      *nats.Conn
	js      nats.JetStreamContext
	bucket  string
	stream  string // "KV_<bucket>"
	filter  string // "$KV.<bucket>.>"
	durable string
	opts    KVSubscriberOptions
	sub     *nats.Subscription
}

// NewKVSubscriber connects to NATS using your config and prepares a subscriber.
// Close() will drain/close the connection (since this constructor owns it).
func NewKVSubscriber(cfg natsc.NATSClientConfig, bucket, durable string,
	o KVSubscriberOptions) (*KVSubscriber, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if bucket == "" || durable == "" {
		return nil, fmt.Errorf("bucket and durable are required")
	}
	setDefaults(&o)

	opts := natsc.NatsOptionsFromConfig("kv-subscriber", cfg)
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect NATS: %w", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream: %w", err)
	}
	s := &KVSubscriber{
		nc:      nc,
		js:      js,
		bucket:  bucket,
		stream:  "KV_" + bucket,
		filter:  "$KV." + bucket + ".>",
		durable: durable,
		opts:    o,
	}
	return s, nil
}

// setDefaults fills in default values for subscriber options.
func setDefaults(o *KVSubscriberOptions) {
	if o.AckWait == 0 {
		o.AckWait = 30 * time.Second
	}
	if o.MaxAckPending == 0 {
		o.MaxAckPending = 1024
	}
	if o.FetchBatchSize <= 0 {
		o.FetchBatchSize = 64
	}
	if o.FetchMaxWait <= 0 {
		o.FetchMaxWait = 2 * time.Second
	}
}

// ensureConsumer makes sure the consumer exists.
func (s *KVSubscriber) ensureConsumer() error {
	deliver := nats.DeliverNewPolicy
	if s.opts.DeliverAll {
		deliver = nats.DeliverAllPolicy
	}
	_, err := s.js.AddConsumer(s.stream, &nats.ConsumerConfig{
		Durable:       s.durable,
		AckPolicy:     nats.AckExplicitPolicy,
		DeliverPolicy: deliver,
		AckWait:       s.opts.AckWait,
		MaxAckPending: s.opts.MaxAckPending,
		FilterSubject: s.filter,
	})
	if err == nil || errors.Is(err, nats.ErrConsumerNameAlreadyInUse) {
		return nil
	}
	return err
}

// StartPull runs the pull loop until ctx is canceled.
// handler must be idempotent; Ack happens only if handler returns nil.
func (s *KVSubscriber) StartPull(ctx context.Context, handler func(context.Context, *KVEvent) error) error {
	if s.js == nil {
		return fmt.Errorf("jetstream not initialized")
	}

	if err := s.ensureConsumer(); err != nil {
		return fmt.Errorf("ensure consumer: %w", err)
	}

	sub, err := s.js.PullSubscribe(s.filter, s.durable, nats.BindStream(s.stream))
	if err != nil {
		return fmt.Errorf("pull subscribe: %w", err)
	}
	s.sub = sub
	defer sub.Unsubscribe()

	batch := s.opts.FetchBatchSize
	maxWait := s.opts.FetchMaxWait

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msgs, err := sub.Fetch(batch, nats.MaxWait(maxWait))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) {
				continue
			}
			if errors.Is(err, nats.ErrNoResponders) {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return fmt.Errorf("fetch: %w", err)
		}

		for _, m := range msgs {
			ev := toEvent(s.bucket, m)

			hErr := handler(ctx, ev)
			if hErr == nil {
				_ = m.Ack()
			} else {
				_ = m.Nak()
			}
		}
	}
}

// Stop unsubscribes from the KV bucket.
func (s *KVSubscriber) Stop() error {
	if s.sub != nil {
		return s.sub.Unsubscribe()
	}
	return nil
}

// Close drains/closes the NATS connection.
func (s *KVSubscriber) Close() {
	if s.nc != nil {
		_ = s.nc.Drain()
		s.nc.Close()
	}
}

// toEvent converts a NATS message to a KVEvent.
func toEvent(bucket string, m *nats.Msg) *KVEvent {
	op := m.Header.Get("KV-Operation")
	var seq uint64
	var ts time.Time
	if md, err := m.Metadata(); err == nil {
		seq = md.Sequence.Stream
		ts = md.Timestamp
	}

	// Subject form: $KV.<bucket>.<key>
	key := ""
	const prefix = "$KV."
	if strings.HasPrefix(m.Subject, prefix) {
		rem := strings.TrimPrefix(m.Subject, prefix)
		parts := strings.SplitN(rem, ".", 2)
		if len(parts) == 2 {
			key = parts[1]
		}
	}

	return &KVEvent{
		Bucket: bucket,
		Key:    key,
		Op:     op,
		Value:  m.Data,
		Seq:    seq,
		Time:   ts,
		Msg:    m,
	}
}
