//go:build windows && cgo

/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tncon

/*
#include <windows.h>
#include <stdlib.h>
#include <synchapi.h>
#include "tncon.h"
*/
import "C"

import (
	"fmt"
	"io"
	"sync"
	"unsafe"
)

var (
	sequenceBuffer *bufferedChannelPipe

	resizeEventSubscribers      []chan struct{}
	resizeEventSubscribersMutex sync.Mutex

	running           bool = false
	runningMutex      sync.Mutex
	runningQuitHandle C.HANDLE
)

func SequenceReader() io.Reader {
	return sequenceBuffer
}

//export writeSequence
func writeSequence(addr *C.char, len C.int) {
	bytes := C.GoBytes(unsafe.Pointer(addr), len)
	sequenceBuffer.Write(bytes)
}

// SubcribeResizeEvents creates a new channel from which to receive console input events.
func SubcribeResizeEvents() chan struct{} {
	resizeEventSubscribersMutex.Lock()
	defer resizeEventSubscribersMutex.Unlock()

	ch := make(chan struct{})
	resizeEventSubscribers = append(resizeEventSubscribers, ch)

	return ch
}

//export notifyResizeEvent
func notifyResizeEvent() {
	resizeEventSubscribersMutex.Lock()
	defer resizeEventSubscribersMutex.Unlock()

	for _, sub := range resizeEventSubscribers {
		sub <- struct{}{}
	}
}

// readInputContinuous is a blocking call that continuously reads console
// input events. Events will be emitted via channels to subscribers. This
// function returns when stdin is closed, or the quit event is triggered.
func readInputContinuous(quitHandle C.HANDLE) error {
	C.ReadInputContinuous(quitHandle)

	// Close the sequenceBuffer (terminal stdin)
	sequenceBuffer.Close()

	// Once finished, close all existing subscriber channels to notify them
	// of the close (they can resubscribe if it's ever restarted).
	resizeEventSubscribersMutex.Lock()
	defer resizeEventSubscribersMutex.Unlock()

	for _, ch := range resizeEventSubscribers {
		close(ch)
	}
	resizeEventSubscribers = resizeEventSubscribers[:0]

	runningMutex.Lock()
	defer runningMutex.Unlock()
	running = false

	// Close the quit event handle.
	if runningQuitHandle != nil {
		C.CloseHandle(runningQuitHandle)
		runningQuitHandle = nil
	}

	return nil
}

// IsRunning determines if a tncon session is currently active.
func IsRunning() bool {
	runningMutex.Lock()
	defer runningMutex.Unlock()

	return running
}

// Start begins a new tncon session, capturing raw input events and emitting
// them as events. Only one session may be active at a time, but sessions can
// be stopped
func Start() error {
	runningMutex.Lock()
	defer runningMutex.Unlock()

	if running {
		return fmt.Errorf("a tncon session is already active")
	}

	running = true
	runningQuitHandle = C.CreateEventA(nil, C.TRUE, C.FALSE, nil)

	// Adding a buffer increases the speed of reads by a great amount,
	// since waiting on channel sends is the main chokepoint. Without
	// a sufficient buffer, the individual keystrokes won't be transmitted
	// quickly enough for them to be grouped as a VT sequence by Windows.
	// A buffer of 100 should provide ample buffer to hold several VT
	// sequences (which are 5 bytes each max) and output them to the
	// terminal in real time.
	sequenceBuffer = newBufferedChannelPipe(100)

	go readInputContinuous(runningQuitHandle)

	return nil
}

// Stop sets the stop event, requesting that the input reader quits. Subscriber
// channels will close shortly after calling, and the subscriber list will be
// cleared.
func Stop() {
	runningMutex.Lock()
	defer runningMutex.Unlock()

	if running && runningQuitHandle != nil {
		C.SetEvent(runningQuitHandle)
	}
}
