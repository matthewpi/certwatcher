// SPDX-License-Identifier: Apache-2.0

package wait

import (
	"context"
	"time"
)

// PollUntilContextCancel tries a condition func until it returns true, an error, or the context
// is cancelled or hits a deadline. condition will be invoked after the first interval if the
// context is not cancelled first. The returned error will be from ctx.Err(), the condition's
// err return value, or nil. If invoking condition takes longer than interval the next condition
// will be invoked immediately. When using very short intervals, condition may be invoked multiple
// times before a context cancellation is detected. If immediate is true, condition will be
// invoked before waiting and guarantees that condition is invoked at least once, regardless of
// whether the context has been cancelled.
func PollUntilContextCancel(ctx context.Context, interval time.Duration, immediate bool, condition ConditionWithContextFunc) error {
	return loopConditionUntilContext(ctx, interval, immediate, condition)
}

// PollUntilContextTimeout will terminate polling after timeout duration by setting a context
// timeout. This is provided as a convenience function for callers not currently executing under
// a deadline and is equivalent to:
//
//	deadlineCtx, deadlineCancel := context.WithTimeout(ctx, timeout)
//	err := PollUntilContextCancel(deadlineCtx, interval, immediate, condition)
//
// The deadline context will be cancelled if the Poll succeeds before the timeout, simplifying
// inline usage. All other behavior is identical to PollUntilContextCancel.
func PollUntilContextTimeout(ctx context.Context, interval, timeout time.Duration, immediate bool, condition ConditionWithContextFunc) error {
	deadlineCtx, deadlineCancel := context.WithTimeout(ctx, timeout)
	defer deadlineCancel()

	return loopConditionUntilContext(deadlineCtx, interval, immediate, condition)
}
