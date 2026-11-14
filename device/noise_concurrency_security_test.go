// SPDX-License-Identifier: MIT
package device

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentGOSTInitiationReplay(t *testing.T) {
	_, responder, _, expected, msg := setupValidationHandshake(t)
	const workers = 12
	var accepted int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			if peer := responder.ConsumeMessageInitiation(msg); peer != nil {
				if peer != expected {
					t.Errorf("unexpected peer accepted")
				}
				atomic.AddInt32(&accepted, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := atomic.LoadInt32(&accepted); got != 1 {
		t.Fatalf("same authenticated initiation accepted %d times; want 1", got)
	}
}

func TestConcurrentGOSTResponseReplay(t *testing.T) {
	initiator, responder, expected, responderPeer, initiation := setupValidationHandshake(t)
	if peer := responder.ConsumeMessageInitiation(initiation); peer != responderPeer {
		t.Fatal("valid initiation rejected")
	}
	response, err := responder.CreateMessageResponse(responderPeer)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 12
	var accepted int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			if peer := initiator.ConsumeMessageResponse(response); peer != nil {
				if peer != expected {
					t.Errorf("unexpected peer accepted")
				}
				atomic.AddInt32(&accepted, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := atomic.LoadInt32(&accepted); got != 1 {
		t.Fatalf("same authenticated response accepted %d times; want 1", got)
	}
}
