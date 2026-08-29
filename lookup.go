package dnsbl2

import (
	"context"
	"errors"
	"sync"
	"time"
)

var errLookupLimit = errors.New("DNS lookup concurrency limit reached")

type resolveResult struct {
	response dnsResponse
	cacheHit bool
	shared   bool
}

type inflightLookup struct {
	done     chan struct{}
	cancel   context.CancelFunc
	waiters  int
	response dnsResponse
	err      error
}

type lookupCoordinator struct {
	ctx       context.Context
	timeout   time.Duration
	cache     *responseCache
	semaphore chan struct{}

	mu       sync.Mutex
	inflight map[string]*inflightLookup
}

func newLookupCoordinator(ctx context.Context, timeout time.Duration, maxConcurrent int, cache *responseCache) *lookupCoordinator {
	if ctx == nil {
		ctx = context.Background()
	}
	return &lookupCoordinator{
		ctx:       ctx,
		timeout:   timeout,
		cache:     cache,
		semaphore: make(chan struct{}, maxConcurrent),
		inflight:  make(map[string]*inflightLookup),
	}
}

func (c *lookupCoordinator) resolve(ctx context.Context, query string, lookupDNS lookupDNSFunc) (resolveResult, error) {
	if response, ok := c.cached(query); ok {
		return resolveResult{response: response, cacheHit: true}, nil
	}

	c.mu.Lock()
	if response, ok := c.cached(query); ok {
		c.mu.Unlock()
		return resolveResult{response: response, cacheHit: true}, nil
	}
	if call, ok := c.inflight[query]; ok {
		call.waiters++
		c.mu.Unlock()
		return c.wait(ctx, query, call, true)
	}
	select {
	case c.semaphore <- struct{}{}:
	default:
		c.mu.Unlock()
		return resolveResult{}, errLookupLimit
	}

	lookupCtx, cancel := context.WithTimeout(c.ctx, c.timeout)
	call := &inflightLookup{
		done:    make(chan struct{}),
		cancel:  cancel,
		waiters: 1,
	}
	c.inflight[query] = call
	c.mu.Unlock()

	go c.run(query, call, lookupCtx, lookupDNS)
	return c.wait(ctx, query, call, false)
}

func (c *lookupCoordinator) cached(query string) (dnsResponse, bool) {
	if c.cache == nil {
		return dnsResponse{}, false
	}
	return c.cache.get(query)
}

func (c *lookupCoordinator) run(query string, call *inflightLookup, ctx context.Context, lookupDNS lookupDNSFunc) {
	response, err := lookupDNS(ctx, query)
	if err == nil && c.cache != nil {
		c.cache.put(query, response)
	}

	call.response = response
	call.err = err
	call.cancel()
	<-c.semaphore

	c.mu.Lock()
	if c.inflight[query] == call {
		delete(c.inflight, query)
	}
	close(call.done)
	c.mu.Unlock()
}

func (c *lookupCoordinator) wait(ctx context.Context, query string, call *inflightLookup, shared bool) (resolveResult, error) {
	select {
	case <-call.done:
		return resolveResult{response: call.response, shared: shared}, call.err
	default:
	}

	select {
	case <-call.done:
		return resolveResult{response: call.response, shared: shared}, call.err
	case <-ctx.Done():
		select {
		case <-call.done:
			return resolveResult{response: call.response, shared: shared}, call.err
		default:
		}
		c.removeWaiter(query, call)
		return resolveResult{}, ctx.Err()
	}
}

func (c *lookupCoordinator) removeWaiter(query string, call *inflightLookup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight[query] != call {
		return
	}
	call.waiters--
	if call.waiters == 0 {
		delete(c.inflight, query)
		call.cancel()
	}
}

func (m *MatchDNSBL) resolve(ctx context.Context, query string, lookupDNS lookupDNSFunc) (resolveResult, error) {
	if m.coordinator != nil {
		return m.coordinator.resolve(ctx, query, lookupDNS)
	}
	if m.cache != nil {
		if response, ok := m.cache.get(query); ok {
			return resolveResult{response: response, cacheHit: true}, nil
		}
	}

	response, err := lookupDNS(ctx, query)
	if err != nil {
		return resolveResult{}, err
	}
	if m.cache != nil {
		m.cache.put(query, response)
	}
	return resolveResult{response: response}, nil
}
