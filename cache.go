package dnsbl2

import (
	"container/list"
	"sync"
	"time"
)

type responseCache struct {
	mu         sync.Mutex
	entries    map[string]*list.Element
	lru        *list.List
	maxEntries int
	maxTTL     time.Duration
	now        func() time.Time
}

type cacheEntry struct {
	key       string
	response  dnsResponse
	expiresAt time.Time
}

func newResponseCache(maxEntries int, maxTTL time.Duration) *responseCache {
	return &responseCache{
		entries:    make(map[string]*list.Element),
		lru:        list.New(),
		maxEntries: maxEntries,
		maxTTL:     maxTTL,
		now:        time.Now,
	}
}

func (c *responseCache) get(key string) (dnsResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	element, ok := c.entries[key]
	if !ok {
		return dnsResponse{}, false
	}
	entry := element.Value.(*cacheEntry)
	if !c.now().Before(entry.expiresAt) {
		c.remove(element)
		return dnsResponse{}, false
	}
	c.lru.MoveToFront(element)
	return entry.response, true
}

func (c *responseCache) put(key string, response dnsResponse) {
	if c.maxEntries <= 0 || response.ttl <= 0 || !cacheableRcode(response.rcode) {
		return
	}

	ttl := response.ttl
	if c.maxTTL > 0 && ttl > c.maxTTL {
		ttl = c.maxTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.entries[key]; ok {
		entry := element.Value.(*cacheEntry)
		entry.response = response
		entry.expiresAt = c.now().Add(ttl)
		c.lru.MoveToFront(element)
		return
	}

	entry := &cacheEntry{
		key:       key,
		response:  response,
		expiresAt: c.now().Add(ttl),
	}
	c.entries[key] = c.lru.PushFront(entry)
	if c.lru.Len() > c.maxEntries {
		c.remove(c.lru.Back())
	}
}

func (c *responseCache) remove(element *list.Element) {
	entry := element.Value.(*cacheEntry)
	delete(c.entries, entry.key)
	c.lru.Remove(element)
}

func cacheableRcode(rcode int) bool {
	return rcode == dnsRcodeSuccess || rcode == dnsRcodeNameError
}
