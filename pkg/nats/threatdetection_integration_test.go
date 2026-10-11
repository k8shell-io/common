//go:build integration

// Run against a JetStream-enabled server:
//
//	docker run -d --rm --name nats-it -p 14222:4222 nats:2.11.9-alpine -js
//	NATS_TEST_URL=nats://127.0.0.1:14222 go test -tags integration ./pkg/nats/ -run ThreatDetection -v
package nats

import (
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestThreatDetectionUpdateAndWatch(t *testing.T) {
	c := testClient(t)
	opts := ThreatDetectionBucketOptions(1)
	opts.Bucket += "-it"
	kv, err := c.NewKV(opts)
	must(t, err, "bucket")
	t.Cleanup(func() { _ = c.js.DeleteKeyValue(opts.Bucket) })

	w, err := kv.WatchAll()
	must(t, err, "watch")
	defer w.Stop()
	if e := <-w.Updates(); e != nil {
		t.Fatalf("empty bucket: want end-of-snapshot marker, got %q", e.Key())
	}

	next := func() nats.KeyValueEntry {
		select {
		case e := <-w.Updates():
			return e
		case <-time.After(5 * time.Second):
			t.Fatal("no update")
			return nil
		}
	}

	// provisioner sets the policy, api-server the override: neither loses the other's field
	must(t, UpdateThreatDetection(kv, "ws-1", func(d *ThreatDetection) {
		d.Policy = &ThreatDetectionPolicy{Detect: "container-escape", EvaluatedFor: "alice"}
	}), "policy")
	next()
	must(t, UpdateThreatDetection(kv, "ws-1", func(d *ThreatDetection) {
		d.Override = &ThreatDetectionOverride{Detect: "all", SetBy: "admin"}
	}), "override")
	d, err := ParseThreatDetection(next().Value())
	must(t, err, "parse")
	if d.Policy == nil || d.Policy.Detect != "container-escape" || d.Override == nil {
		t.Fatalf("entry = %+v", d)
	}
	if ob, _ := d.Resolve(); !ob.All {
		t.Fatalf("override not applied: %+v", ob)
	}

	// clearing the override falls back to the policy
	must(t, UpdateThreatDetection(kv, "ws-1", func(d *ThreatDetection) { d.Override = nil }), "clear")
	d, err = ParseThreatDetection(next().Value())
	must(t, err, "parse")
	if ob, found := d.Resolve(); !found || ob.All || len(ob.Categories) != 1 {
		t.Fatalf("after clear: %+v %v", ob, found)
	}

	// removing the last field deletes the entry
	must(t, UpdateThreatDetection(kv, "ws-1", func(d *ThreatDetection) { d.Policy = nil }), "delete")
	if e := next(); e.Operation() != nats.KeyValueDelete {
		t.Fatalf("want delete, got %v", e.Operation())
	}
	if _, err := kv.Get("ws-1"); !errors.Is(err, nats.ErrKeyNotFound) {
		t.Fatalf("entry still present: %v", err)
	}
}
