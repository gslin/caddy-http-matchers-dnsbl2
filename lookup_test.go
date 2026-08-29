package dnsbl2

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestLookupCoordinatorCoalescesQueries(t *testing.T) {
	const callers = 10

	coordinator := newLookupCoordinator(context.Background(), time.Second, callers, nil)
	started := make(chan struct{})
	release := make(chan struct{})
	var lookups atomic.Int32
	lookup := func(context.Context, string) (dnsResponse, error) {
		if lookups.Add(1) == 1 {
			close(started)
		}
		<-release
		return dnsResponse{rcode: dnsRcodeSuccess}, nil
	}

	results := make(chan resolveResult, callers)
	errors := make(chan error, callers)
	start := make(chan struct{})
	for range callers {
		go func() {
			<-start
			result, err := coordinator.resolve(context.Background(), "same.example.", lookup)
			results <- result
			errors <- err
		}()
	}
	close(start)
	<-started
	waitForLookupWaiters(t, coordinator, "same.example.", callers)
	close(release)

	shared := 0
	for range callers {
		if err := <-errors; err != nil {
			t.Errorf("resolve: %v", err)
		}
		if (<-results).shared {
			shared++
		}
	}
	if got, want := lookups.Load(), int32(1); got != want {
		t.Fatalf("DNS lookups = %d, want %d", got, want)
	}
	if got, want := shared, callers-1; got != want {
		t.Fatalf("shared results = %d, want %d", got, want)
	}
}

func TestLookupCoordinatorEnforcesConcurrencyLimit(t *testing.T) {
	coordinator := newLookupCoordinator(context.Background(), time.Second, 1, nil)
	started := make(chan struct{})
	release := make(chan struct{})
	lookup := func(context.Context, string) (dnsResponse, error) {
		close(started)
		<-release
		return dnsResponse{rcode: dnsRcodeSuccess}, nil
	}

	done := make(chan error, 1)
	go func() {
		_, err := coordinator.resolve(context.Background(), "one.example.", lookup)
		done <- err
	}()
	<-started

	if _, err := coordinator.resolve(context.Background(), "two.example.", lookup); !errors.Is(err, errLookupLimit) {
		t.Fatalf("resolve error = %v, want %v", err, errLookupLimit)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first resolve: %v", err)
	}
}

func TestLookupCoordinatorKeepsSharedLookupAlive(t *testing.T) {
	coordinator := newLookupCoordinator(context.Background(), time.Second, 1, nil)
	release := make(chan struct{})
	lookupCanceled := make(chan struct{})
	lookup := func(ctx context.Context, _ string) (dnsResponse, error) {
		select {
		case <-release:
			return dnsResponse{rcode: dnsRcodeSuccess}, nil
		case <-ctx.Done():
			close(lookupCanceled)
			return dnsResponse{}, ctx.Err()
		}
	}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() {
		_, err := coordinator.resolve(firstCtx, "same.example.", lookup)
		firstDone <- err
	}()
	go func() {
		_, err := coordinator.resolve(context.Background(), "same.example.", lookup)
		secondDone <- err
	}()
	waitForLookupWaiters(t, coordinator, "same.example.", 2)

	cancelFirst()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first resolve error = %v, want context cancellation", err)
	}
	select {
	case <-lookupCanceled:
		t.Fatal("shared DNS lookup was canceled")
	default:
	}

	close(release)
	if err := <-secondDone; err != nil {
		t.Fatalf("second resolve: %v", err)
	}
}

func TestLookupCoordinatorCancelsLookupWithoutWaiters(t *testing.T) {
	coordinator := newLookupCoordinator(context.Background(), time.Second, 1, nil)
	lookupCanceled := make(chan struct{})
	lookup := func(ctx context.Context, _ string) (dnsResponse, error) {
		<-ctx.Done()
		close(lookupCanceled)
		return dnsResponse{}, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := coordinator.resolve(ctx, "same.example.", lookup)
		done <- err
	}()
	waitForLookupWaiters(t, coordinator, "same.example.", 1)
	cancel()

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("resolve error = %v, want context cancellation", err)
	}
	select {
	case <-lookupCanceled:
	case <-time.After(time.Second):
		t.Fatal("DNS lookup was not canceled")
	}
}

func waitForLookupWaiters(t *testing.T, coordinator *lookupCoordinator, query string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		coordinator.mu.Lock()
		call := coordinator.inflight[query]
		got := 0
		if call != nil {
			got = call.waiters
		}
		coordinator.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("lookup did not reach %d waiters", want)
}
