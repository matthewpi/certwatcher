// SPDX-License-Identifier: Apache-2.0

package wait

import (
	"context"
	"time"
)

// ConditionWithContextFunc returns true if the condition is satisfied, or an error
// if the loop should be aborted.
//
// The caller passes along a context that can be used by the condition function.
type ConditionWithContextFunc func(context.Context) (done bool, err error)

// loopConditionUntilContext executes the provided condition at intervals defined by
// the provided timer until the provided context is cancelled, the condition returns
// true, or the condition returns an error. If sliding is true, the period is computed
// after condition runs. If it is false then period includes the runtime for condition.
// If immediate is false the first delay happens before any call to condition, if
// immediate is true the condition will be invoked before waiting and guarantees that
// the condition is invoked at least once, regardless of whether the context has been
// cancelled. The returned error is the error returned by the last condition or the
// context error if the context was terminated.
//
// This is the common loop construct for all polling in the wait package.
func loopConditionUntilContext(ctx context.Context, interval time.Duration, immediate bool, condition ConditionWithContextFunc) error {
	t := newRealTimer()
	defer t.Stop()

	doneCh := ctx.Done()

	var timeCh <-chan time.Time
	timeCh = t.C()

	// if immediate is true the condition is
	// guaranteed to be executed at least once,
	// if we haven't requested immediate execution, delay once
	if immediate {
		if ok, err := func() (bool, error) {
			// defer runtime.HandleCrash()
			return condition(ctx)
		}(); err != nil || ok {
			return err
		}
	}

	for {
		// Wait for either the context to be cancelled or the next invocation be called
		select {
		case <-doneCh:
			return ctx.Err()
		case <-timeCh:
		}

		// IMPORTANT: Because there is no channel priority selection in golang
		// it is possible for very short timers to "win" the race in the previous select
		// repeatedly even when the context has been canceled.  We therefore must
		// explicitly check for context cancellation on every loop and exit if true to
		// guarantee that we don't invoke condition more than once after context has
		// been cancelled.
		if err := ctx.Err(); err != nil {
			return err
		}

		t.Start(interval)

		if ok, err := func() (bool, error) {
			// defer runtime.HandleCrash()
			return condition(ctx)
		}(); err != nil || ok {
			return err
		}
	}
}
