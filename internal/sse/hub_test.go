package sse

import (
	"context"
	"testing"
	"time"
)

func TestHubSubscribe(t *testing.T) {
	h := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.Subscribe(ctx, 1)

	h.Publish([]byte("a"))
	select {
	case b := <-ch:
		if string(b) != "a" {
			t.Fatalf("got %s", b)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout")
	}
}

func TestHubOverflow(t *testing.T) {
	h := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.Subscribe(ctx, 1)

	h.Publish([]byte("1"))
	h.Publish([]byte("2"))

	if got := <-ch; string(got) != "1" {
		t.Fatalf("first %s", got)
	}
	select {
	case <-ch:
		t.Fatal("should drop second event")
	default:
	}
}

func TestHubDisconnect(t *testing.T) {
	h := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	ch := h.Subscribe(ctx, 1)
	cancel()
	time.Sleep(10 * time.Millisecond)
	h.Publish([]byte("x"))
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closed")
		}
	default:
		t.Fatal("channel not closed")
	}
}

func TestHubMultipleSubscribers(t *testing.T) {
	h := NewHub()
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	ch1 := h.Subscribe(ctx1, 1)
	ch2 := h.Subscribe(ctx2, 1)

	h.Publish([]byte("ping"))

	select {
	case b := <-ch1:
		if string(b) != "ping" {
			t.Fatalf("ch1 got %s", b)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout ch1")
	}
	select {
	case b := <-ch2:
		if string(b) != "ping" {
			t.Fatalf("ch2 got %s", b)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout ch2")
	}
}

func TestHubLateSubscriber(t *testing.T) {
	h := NewHub()
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	ch1 := h.Subscribe(ctx1, 1)
	h.Publish([]byte("early"))
	if got := <-ch1; string(got) != "early" {
		t.Fatalf("first %s", got)
	}

	ch2 := h.Subscribe(context.Background(), 1)
	select {
	case <-ch2:
		t.Fatal("late subscriber should not receive old event")
	default:
	}

	h.Publish([]byte("late"))
	want := []byte("late")
	select {
	case b := <-ch1:
		if string(b) != string(want) {
			t.Fatalf("ch1 got %s", b)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout ch1 late")
	}
	select {
	case b := <-ch2:
		if string(b) != string(want) {
			t.Fatalf("ch2 got %s", b)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout ch2 late")
	}
}
func TestHubConcurrentPublishAndCancel(t *testing.T) {
	h := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	ch := h.Subscribe(ctx, 1)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			h.Publish([]byte("x"))
			time.Sleep(time.Millisecond)
		}
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done

	// Wait for the channel to close. It may still contain buffered events, so
	// keep reading until it is closed or a timeout occurs.
	timeout := time.After(100 * time.Millisecond)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("channel not closed")
		}
	}
}
