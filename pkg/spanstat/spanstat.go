// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spanstat

import (
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/safetime"
	"github.com/cilium/cilium/pkg/time"
)

// SpanStat measures the total duration of all time spent in between Start()
// and Stop() calls.
type SpanStat struct {
	mutex           lock.RWMutex
	spanStart       time.Time
	successDuration time.Duration
	failureDuration time.Duration
}

// Start creates a new SpanStat and starts it
func Start() *SpanStat {
	s := &SpanStat{}
	return s.Start()
}

// Start starts a new span
func (s *SpanStat) Start() *SpanStat {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.spanStart = time.Now()
	return s
}

// EndError calls End() based on the value of err
func (s *SpanStat) EndError(err error) *SpanStat {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.end(err == nil)
}

// End ends the current span and adds the measured duration to the total
// cumulated duration, and to the success or failure cumulated duration
// depending on the given success flag
func (s *SpanStat) End(success bool) *SpanStat {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.end(success)
}

// must be called with Lock() held
func (s *SpanStat) end(success bool) *SpanStat {
	if !s.spanStart.IsZero() {
		// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
		d, _ := safetime.TimeSinceSafe(s.spanStart, logging.DefaultSlogLogger)
		if success {
			s.successDuration += d
		} else {
			s.failureDuration += d
		}
	}
	s.spanStart = time.Time{}
	return s
}

// Total returns the total duration of all spans measured, including both
// successes and failures
func (s *SpanStat) Total() time.Duration {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.successDuration + s.failureDuration
}

// SuccessTotal returns the total duration of all successful spans measured
func (s *SpanStat) SuccessTotal() time.Duration {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.successDuration
}

// FailureTotal returns the total duration of all unsuccessful spans measured
func (s *SpanStat) FailureTotal() time.Duration {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.failureDuration
}

// Reset rests the duration measurements
func (s *SpanStat) Reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.successDuration = 0
	s.failureDuration = 0
}

// Seconds returns the number of seconds represents by the spanstat. If a span
// is still open, it is closed first.
func (s *SpanStat) Seconds() float64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if !s.spanStart.IsZero() {
		s.end(true)
	}

	total := s.successDuration + s.failureDuration
	return total.Seconds()
}
