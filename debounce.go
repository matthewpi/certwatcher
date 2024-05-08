// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 Matthew Penner

package certwatcher

import (
	"sync"
	"time"
)

// debounced is a debounced function call.
type debounced func(func())

// debounce returns a debounced function that takes another functions as an
// argument. This function will be called when the debounced function stops
// being called for the given duration. The debounced function can be invoked
// with different functions if necessary, the last one will win.
func debounce(after time.Duration) debounced {
	d := &debouncer{after: after}

	return func(f func()) {
		d.add(f)
	}
}

// debouncer is used to debounce a function call.
type debouncer struct {
	mx    sync.Mutex
	after time.Duration
	timer *time.Timer
}

// add adds a function call to the debouncer.
func (d *debouncer) add(f func()) {
	d.mx.Lock()
	defer d.mx.Unlock()
	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.after, f)
}
