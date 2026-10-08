package nats

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/k8shell-io/common/pkg/logger"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

// StreamOptions describes a JetStream stream for EnsureStream.
type StreamOptions struct {
	Name     string
	Subjects []string
	// MaxAge is how long messages are kept. Default 24h.
	MaxAge time.Duration
	// MaxBytes caps the stream size; the oldest messages are discarded first.
	// Default 1 GiB.
	MaxBytes int64
	// Replicas is the number of server replicas; it must not exceed the size
	// of the NATS cluster. Default 3.
	Replicas int
	// Duplicates is the window in which a repeated message ID is dropped.
	// Default 5m.
	Duplicates time.Duration
}

func setStreamDefaults(o *StreamOptions) {
	if o.MaxAge == 0 {
		o.MaxAge = 24 * time.Hour
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 1 << 30
	}
	if o.Replicas <= 0 {
		o.Replicas = 3
	}
	if o.Duplicates == 0 {
		o.Duplicates = 5 * time.Minute
	}
}

// jetStream returns the client's JetStream context, creating it on first use.
func (c *NATSClient) jetStream() (nats.JetStreamContext, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nc == nil {
		return nil, fmt.Errorf("NATS connection is not established")
	}
	if c.js == nil {
		js, err := c.nc.JetStream()
		if err != nil {
			return nil, err
		}
		c.js = js
	}
	return c.js, nil
}

// EnsureStream creates the stream, or updates it to the given options if it
// already exists. It is idempotent and safe to call from several replicas.
func (c *NATSClient) EnsureStream(opts StreamOptions) error {
	if opts.Name == "" || len(opts.Subjects) == 0 {
		return errors.New("stream: name and subjects are required")
	}
	setStreamDefaults(&opts)

	js, err := c.jetStream()
	if err != nil {
		return err
	}

	cfg := &nats.StreamConfig{
		Name:       opts.Name,
		Subjects:   opts.Subjects,
		Retention:  nats.LimitsPolicy,
		Storage:    nats.FileStorage,
		Discard:    nats.DiscardOld,
		MaxAge:     opts.MaxAge,
		MaxBytes:   opts.MaxBytes,
		Replicas:   opts.Replicas,
		Duplicates: opts.Duplicates,
	}

	if _, err := js.StreamInfo(opts.Name); err != nil {
		if !errors.Is(err, nats.ErrStreamNotFound) {
			return fmt.Errorf("stream info: %w", err)
		}
		if _, err := js.AddStream(cfg); err == nil {
			return nil
		} else if !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
			return fmt.Errorf("add stream: %w", err)
		}
		// Lost a creation race with another replica: fall through to update.
	}
	if _, err := js.UpdateStream(cfg); err != nil {
		return fmt.Errorf("update stream: %w", err)
	}
	return nil
}

// StreamPublisherOptions tunes a StreamPublisher.
type StreamPublisherOptions struct {
	// MaxPending bounds unacknowledged messages in flight. Default 4096.
	MaxPending int
	// MaxRetries is how often a message that failed (no ack, no stream yet,
	// server down) is republished before it is dropped. Default 10.
	MaxRetries int
	// MaxBackoff caps the delay between retries, which start at 1s and double.
	// Default 30s.
	MaxBackoff time.Duration
	// MaxRetryQueue bounds messages waiting for a retry; beyond it, failed
	// messages are dropped. Default 10000.
	MaxRetryQueue int
}

// StreamPublisher publishes to JetStream without blocking the caller: a
// message is handed to the client, acknowledged asynchronously, and republished
// with backoff if that fails. Delivery is at-least-once; the message ID makes
// JetStream drop duplicates within the stream's duplicate window.
type StreamPublisher struct {
	log  *zerolog.Logger
	js   nats.JetStreamContext
	opts StreamPublisherOptions

	retrying atomic.Int64
	retried  atomic.Uint64
	dropped  atomic.Uint64
}

const attemptHeader = "X-Publish-Attempt"

// NewStreamPublisher creates a publisher on the client's connection.
func (c *NATSClient) NewStreamPublisher(opts StreamPublisherOptions) (*StreamPublisher, error) {
	if opts.MaxPending <= 0 {
		opts.MaxPending = 4096
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = 10
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 30 * time.Second
	}
	if opts.MaxRetryQueue <= 0 {
		opts.MaxRetryQueue = 10000
	}

	p := &StreamPublisher{log: logger.NewLogger("nats-publisher"), opts: opts}

	c.mu.RLock()
	nc := c.nc
	c.mu.RUnlock()
	if nc == nil {
		return nil, fmt.Errorf("NATS connection is not established")
	}
	js, err := nc.JetStream(
		nats.PublishAsyncMaxPending(opts.MaxPending),
		nats.PublishAsyncErrHandler(p.onError),
	)
	if err != nil {
		return nil, err
	}
	p.js = js
	return p, nil
}

// Publish queues data on subject. msgID, if set, is the deduplication ID.
// It returns an error only if the message could not even be handed to the
// client (too many unacknowledged messages); later failures are retried.
func (p *StreamPublisher) Publish(subject string, data []byte, msgID string) error {
	msg := nats.NewMsg(subject)
	msg.Data = data
	if msgID != "" {
		msg.Header.Set(nats.MsgIdHdr, msgID)
	}
	msg.Header.Set(attemptHeader, "1")
	_, err := p.js.PublishMsgAsync(msg)
	return err
}

// onError runs when a message was not acknowledged: retry it later, or drop it.
func (p *StreamPublisher) onError(_ nats.JetStream, msg *nats.Msg, err error) {
	attempt, _ := strconv.Atoi(msg.Header.Get(attemptHeader))
	if attempt >= p.opts.MaxRetries || p.retrying.Load() >= int64(p.opts.MaxRetryQueue) {
		p.dropped.Add(1)
		p.log.Error().Err(err).Str("subject", msg.Subject).Str("id", msg.Header.Get(nats.MsgIdHdr)).
			Int("attempts", attempt).Msg("Dropping message after failed publish")
		return
	}

	backoff := time.Second << min(attempt-1, 16)
	backoff = min(backoff, p.opts.MaxBackoff)
	p.log.Warn().Err(err).Str("subject", msg.Subject).Int("attempt", attempt).
		Dur("retry_in", backoff).Msg("Publish failed, will retry")

	retry := nats.NewMsg(msg.Subject)
	retry.Data = msg.Data
	for k, v := range msg.Header {
		retry.Header[k] = v
	}
	retry.Header.Set(attemptHeader, strconv.Itoa(attempt+1))

	p.retrying.Add(1)
	p.retried.Add(1)
	time.AfterFunc(backoff, func() {
		p.retrying.Add(-1)
		if _, err := p.js.PublishMsgAsync(retry); err != nil {
			p.onError(p.js, retry, err)
		}
	})
}

// Stats reports messages republished after a failure and messages dropped.
func (p *StreamPublisher) Stats() (retried, dropped uint64) {
	return p.retried.Load(), p.dropped.Load()
}

// Flush waits until all in-flight messages are acknowledged or ctx ends.
func (p *StreamPublisher) Flush(ctx context.Context) error {
	select {
	case <-p.js.PublishAsyncComplete():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ErrDiscard, wrapped in a handler's error, makes the subscriber terminate the
// message instead of redelivering it (e.g. a payload that can never be parsed).
var ErrDiscard = errors.New("discard message")

// StreamMessage is a message delivered by a StreamSubscriber.
type StreamMessage struct {
	Subject string
	Data    []byte
	// Seq is the stream sequence; Time is when the stream stored the message.
	Seq  uint64
	Time time.Time
	// Deliveries is how many times this message was delivered (1 on first).
	Deliveries uint64
}

// StreamSubscriberOptions tunes a StreamSubscriber.
type StreamSubscriberOptions struct {
	// FilterSubject restricts the consumer to matching subjects; empty means
	// the whole stream.
	FilterSubject string
	// DeliverAll starts a new consumer at the oldest stored message instead of
	// only new ones. Has no effect on an existing durable consumer.
	DeliverAll bool
	// AckWait is how long a handler may take before redelivery. Default 30s.
	AckWait time.Duration
	// MaxDeliver bounds redeliveries of a failing message. Default 10.
	MaxDeliver int
	// MaxAckPending bounds unacknowledged messages. Default 1024.
	MaxAckPending  int
	FetchBatchSize int
	FetchMaxWait   time.Duration
}

// StreamSubscriber pulls messages from a durable consumer. Subscribers that
// share a durable name share the work: each message goes to one of them.
type StreamSubscriber struct {
	log     *zerolog.Logger
	js      nats.JetStreamContext
	stream  string
	durable string
	opts    StreamSubscriberOptions
}

// NewStreamSubscriber prepares a subscriber on the stream's durable consumer.
func (c *NATSClient) NewStreamSubscriber(stream, durable string, o StreamSubscriberOptions) (*StreamSubscriber, error) {
	if stream == "" || durable == "" {
		return nil, errors.New("stream and durable are required")
	}
	if o.AckWait == 0 {
		o.AckWait = 30 * time.Second
	}
	if o.MaxDeliver == 0 {
		o.MaxDeliver = 10
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
	js, err := c.jetStream()
	if err != nil {
		return nil, err
	}
	return &StreamSubscriber{log: logger.NewLogger("nats-subscriber"), js: js, stream: stream, durable: durable, opts: o}, nil
}

func (s *StreamSubscriber) subscribe() (*nats.Subscription, error) {
	deliver := nats.DeliverNewPolicy
	if s.opts.DeliverAll {
		deliver = nats.DeliverAllPolicy
	}
	_, err := s.js.AddConsumer(s.stream, &nats.ConsumerConfig{
		Durable:       s.durable,
		AckPolicy:     nats.AckExplicitPolicy,
		DeliverPolicy: deliver,
		AckWait:       s.opts.AckWait,
		MaxDeliver:    s.opts.MaxDeliver,
		MaxAckPending: s.opts.MaxAckPending,
		FilterSubject: s.opts.FilterSubject,
	})
	if err != nil && !errors.Is(err, nats.ErrConsumerNameAlreadyInUse) {
		return nil, fmt.Errorf("ensure consumer: %w", err)
	}
	sub, err := s.js.PullSubscribe(s.opts.FilterSubject, s.durable, nats.BindStream(s.stream))
	if err != nil {
		return nil, fmt.Errorf("pull subscribe: %w", err)
	}
	return sub, nil
}

// Run delivers messages to handler until ctx is cancelled. A message is
// acknowledged when handler returns nil, terminated when the error wraps
// ErrDiscard, and redelivered shortly after for any other error (up to
// MaxDeliver times). If the stream or consumer disappears, or the server is
// unreachable, Run re-establishes the subscription instead of returning.
func (s *StreamSubscriber) Run(ctx context.Context, handler func(context.Context, *StreamMessage) error) error {
	for ctx.Err() == nil {
		sub, err := s.subscribe()
		if err != nil {
			s.log.Warn().Err(err).Msg("Cannot subscribe yet, retrying")
			if !sleep(ctx, 2*time.Second) {
				break
			}
			continue
		}

		err = s.pull(ctx, sub, handler)
		_ = sub.Unsubscribe()
		if ctx.Err() != nil {
			break
		}
		s.log.Warn().Err(err).Msg("Subscription lost, re-establishing")
		if !sleep(ctx, 2*time.Second) {
			break
		}
	}
	return ctx.Err()
}

func (s *StreamSubscriber) pull(ctx context.Context, sub *nats.Subscription, handler func(context.Context, *StreamMessage) error) error {
	for ctx.Err() == nil {
		msgs, err := sub.Fetch(s.opts.FetchBatchSize, nats.MaxWait(s.opts.FetchMaxWait))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) {
				continue
			}
			return fmt.Errorf("fetch: %w", err)
		}
		for _, m := range msgs {
			sm := &StreamMessage{Subject: m.Subject, Data: m.Data}
			if md, err := m.Metadata(); err == nil {
				sm.Seq, sm.Time, sm.Deliveries = md.Sequence.Stream, md.Timestamp, md.NumDelivered
			}
			switch hErr := handler(ctx, sm); {
			case hErr == nil:
				_ = m.Ack()
			case errors.Is(hErr, ErrDiscard):
				s.log.Warn().Err(hErr).Str("subject", m.Subject).Uint64("seq", sm.Seq).Msg("Discarding message")
				_ = m.Term()
			default:
				s.log.Warn().Err(hErr).Str("subject", m.Subject).Uint64("seq", sm.Seq).Msg("Handler failed, message will be redelivered")
				_ = m.NakWithDelay(2 * time.Second)
			}
		}
	}
	return ctx.Err()
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// DeleteStream removes a stream and its messages. Services do not normally
// call it; it exists for tests and tooling.
func (c *NATSClient) DeleteStream(name string) error {
	js, err := c.jetStream()
	if err != nil {
		return err
	}
	if err := js.DeleteStream(name); err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
		return err
	}
	return nil
}
