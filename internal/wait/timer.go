// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 Matthew Penner

package wait

import "time"

// realTimer implements the Timer interface by wrapping a [time.Timer].
type realTimer struct {
	timer *time.Timer
}

// newRealTimer returns a new real timer.
func newRealTimer() *realTimer {
	return &realTimer{}
}

func (t *realTimer) C() <-chan time.Time {
	if t.timer == nil {
		return nil
	}
	return t.timer.C
}

func (t *realTimer) Start(d time.Duration) {
	if t.timer == nil {
		t.timer = time.NewTimer(d)
		return
	}
	t.timer.Reset(d)
}

func (t *realTimer) Stop() bool {
	if t.timer == nil {
		return true
	}
	return t.timer.Stop()
}
