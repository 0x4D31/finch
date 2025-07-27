package sse

import (
	"context"
	"sync"
)

// Hub delivers published events to multiple subscribers.
type Hub struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
}

// NewHub creates a Hub.
func NewHub() *Hub {
	return &Hub{clients: make(map[chan []byte]struct{})}
}

// Publish sends the event to all subscribers, dropping it for any
// subscriber whose buffer is full.
func (h *Hub) Publish(ev []byte) {
	// Copy the current set of subscribers under the read lock so that we can
	// release the lock before sending events. Holding the lock while
	// iterating would block Subscribe/Unsubscribe calls, which need the
	// write lock. By copying we minimize the time the lock is held.
	h.mu.RLock()
	clients := make([]chan []byte, 0, len(h.clients))
	for ch := range h.clients {
		clients = append(clients, ch)
	}
	h.mu.RUnlock()

	// Now send the event to the copied list of subscribers. A subscriber
	// might have been removed and its channel closed after we released the
	// lock, so recover from a potential send on a closed channel.
	for _, ch := range clients {
		func() {
			defer func() { _ = recover() }()
			select {
			case ch <- ev:
			default:
			}
		}()
	}
}

// Subscribe registers a new subscriber with the given buffer size.
// The returned channel is closed when the context is done.
func (h *Hub) Subscribe(ctx context.Context, buf int) <-chan []byte {
	if buf <= 0 {
		buf = 1
	}
	ch := make(chan []byte, buf)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()

	go func() {
		<-ctx.Done()
		h.mu.Lock()
		delete(h.clients, ch)
		close(ch)
		h.mu.Unlock()
	}()
	return ch
}
