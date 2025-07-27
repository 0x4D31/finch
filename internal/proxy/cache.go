package proxy

import (
	"container/list"
	"net/http"
	"sync"

	"github.com/0x4D31/fingerproxy/pkg/reverseproxy"
)

// proxyCache implements a basic LRU cache for HTTP handlers.
type proxyCache struct {
	size int
	mu   sync.Mutex
	ll   *list.List
	m    map[string]*list.Element
}

type cacheEntry struct {
	key string
	val *reverseproxy.HTTPHandler
	tr  *http.Transport
}

// closeAll iterates over all cached handlers and closes idle connections on
// their transports. It should be called when shutting down the server to
// ensure no lingering connections remain.
func (c *proxyCache) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for e := c.ll.Front(); e != nil; e = e.Next() {
		if ce, ok := e.Value.(*cacheEntry); ok {
			if ce.tr != nil {
				ce.tr.CloseIdleConnections()
			}
		}
	}
}

func newProxyCache(size int) *proxyCache {
	if size <= 0 {
		size = DefaultProxyCacheSize
	}
	return &proxyCache{
		size: size,
		ll:   list.New(),
		m:    make(map[string]*list.Element, size+1),
	}
}

func (c *proxyCache) Get(key string) (*reverseproxy.HTTPHandler, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, ok := c.m[key]; ok {
		c.ll.MoveToFront(ele)
		return ele.Value.(*cacheEntry).val, true
	}
	return nil, false
}

func (c *proxyCache) Add(key string, val *reverseproxy.HTTPHandler, tr *http.Transport) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, ok := c.m[key]; ok {
		c.ll.MoveToFront(ele)
		ce := ele.Value.(*cacheEntry)
		ce.val = val
		ce.tr = tr
		return
	}
	ele := c.ll.PushFront(&cacheEntry{key: key, val: val, tr: tr})
	c.m[key] = ele
	if c.ll.Len() > c.size {
		c.removeOldest()
	}
}

func (c *proxyCache) removeOldest() {
	ele := c.ll.Back()
	if ele == nil {
		return
	}
	c.ll.Remove(ele)
	ent := ele.Value.(*cacheEntry)
	delete(c.m, ent.key)
	if ent.tr != nil {
		ent.tr.CloseIdleConnections()
	}
}
