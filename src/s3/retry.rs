//! How long a call keeps trying, and how long it waits between tries.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{Instant, sleep, timeout_at};
use tracing::{debug, error, warn};

use super::error::S3Error;
use crate::utils::fill_random;

/// Attempts a foreground call makes at most.
pub(crate) const FOREGROUND_ATTEMPTS: u32 = 5;

/// Failures after which a background call logs each further failure at warn
/// level.
pub(crate) const QUIET_FAILURES: u32 = 3;

/// The wait after the first failure is drawn from `0..=BASE_DELAY`.
pub(crate) const BASE_DELAY: Duration = Duration::from_millis(100);
const FOREGROUND_CAP: Duration = Duration::from_secs(5);
const BACKGROUND_CAP: Duration = Duration::from_secs(60);
/// The deadline of a call whose timeout overflows the clock.
const FAR_FUTURE: Duration = Duration::from_hours(24 * 365 * 30);

/// A signal that ends the background calls that hold it. Clones share it.
#[derive(Debug, Clone)]
pub(crate) struct Stop(Arc<watch::Sender<bool>>);

impl Stop {
    pub(crate) fn new() -> Self {
        Stop(Arc::new(watch::Sender::new(false)))
    }

    /// Ends the calls: no attempt begins from now on, and a wait before the
    /// next attempt ends at once. An attempt under way runs to its end.
    pub(crate) fn stop(&self) {
        self.0.send_replace(true);
    }

    pub(crate) fn is_stopped(&self) -> bool {
        *self.0.borrow()
    }

    pub(crate) async fn stopped(&self) {
        let mut state = self.0.subscribe();
        // The sender lives in `self`, so the wait ends only with the signal.
        let _ = state.wait_for(|stopped| *stopped).await;
    }
}

/// How a call treats failures that trying again can fix.
#[derive(Debug, Clone)]
pub(crate) enum Retry {
    /// Work for a request a client waits on: at most [`FOREGROUND_ATTEMPTS`]
    /// attempts, none started and none left running at `deadline`.
    Foreground { deadline: Instant },
    /// Work nobody waits on: tries again for as long as the failure is one
    /// that trying again can fix, or until `stop` is called.
    Background { stop: Stop },
}

/// The instant `timeout` from now. A `timeout` too long for the clock gives a
/// deadline decades away.
pub(crate) fn deadline_after(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout).unwrap_or(now + FAR_FUTURE)
}

impl Retry {
    /// A foreground call that has `timeout` from now.
    pub(crate) fn within(timeout: Duration) -> Self {
        Retry::Foreground {
            deadline: deadline_after(timeout),
        }
    }

    /// A background call nothing stops.
    #[cfg_attr(not(test), expect(dead_code, reason = "called by tests only"))]
    pub(crate) fn background() -> Self {
        Retry::Background { stop: Stop::new() }
    }

    /// A background call that ends when `stop` is called.
    pub(crate) fn until(stop: &Stop) -> Self {
        Retry::Background { stop: stop.clone() }
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        match self {
            Retry::Foreground { deadline } => Some(*deadline),
            Retry::Background { .. } => None,
        }
    }

    fn cap(&self) -> Duration {
        match self {
            Retry::Foreground { .. } => FOREGROUND_CAP,
            Retry::Background { .. } => BACKGROUND_CAP,
        }
    }

    /// Whether another attempt is allowed after `failures` failed ones.
    pub(crate) fn allows_another(&self, failures: u32) -> bool {
        match self {
            Retry::Foreground { .. } => failures < FOREGROUND_ATTEMPTS,
            Retry::Background { .. } => true,
        }
    }

    /// Whether `error` is one that this call tries again after. A clock the
    /// store rejects is, in a background call.
    fn retries(&self, error: &S3Error) -> bool {
        error.is_transient() || (matches!(self, Retry::Background { .. }) && error.is_clock_skew())
    }

    /// Whether the failure number `failures` of a call is logged at warn
    /// level: those of a background call after the first [`QUIET_FAILURES`].
    fn warns(&self, failures: u32) -> bool {
        matches!(self, Retry::Background { .. }) && failures > QUIET_FAILURES
    }

    /// How long to wait after `failures` failed attempts: a random time up to
    /// `base`, doubled for each earlier failure, and up to the cap at most.
    pub(crate) fn delay(&self, failures: u32, base: Duration) -> Duration {
        jitter(delay_bound(failures, base, self.cap()))
    }
}

/// The attempts of one call. A call runs each attempt through
/// [`attempt`](Self::attempt) and hands each failure to
/// [`failed`](Self::failed), which waits and returns when another attempt may
/// follow.
#[derive(Debug)]
pub(crate) struct Attempts {
    retry: Retry,
    base: Duration,
    failures: u32,
}

impl Attempts {
    pub(crate) fn new(retry: Retry, base: Duration) -> Self {
        Attempts {
            retry,
            base,
            failures: 0,
        }
    }

    /// The number of attempts that have failed.
    pub(crate) fn failures(&self) -> u32 {
        self.failures
    }

    /// Runs one attempt. A foreground attempt that has not finished at the
    /// deadline is dropped and fails with [`S3Error::DeadlineExceeded`]. A
    /// background attempt does not begin once the call is stopped, and fails
    /// with [`S3Error::Stopped`]; one that has begun is never cut short.
    pub(crate) async fn attempt<T>(
        &self,
        work: impl Future<Output = Result<T, S3Error>>,
    ) -> Result<T, S3Error> {
        match &self.retry {
            Retry::Foreground { deadline } => {
                if Instant::now() >= *deadline {
                    return Err(S3Error::DeadlineExceeded);
                }
                timeout_at(*deadline, work)
                    .await
                    .unwrap_or(Err(S3Error::DeadlineExceeded))
            }
            Retry::Background { stop } => {
                if stop.is_stopped() {
                    return Err(S3Error::Stopped);
                }
                work.await
            }
        }
    }

    /// Takes note of a failed attempt. Returns once the wait before the next
    /// attempt is over, or with the error to give the caller when the failure
    /// is final: an error trying again cannot fix, a foreground call out of
    /// attempts, a wait that would end past the deadline, or a stopped
    /// background call, which fails with [`S3Error::Stopped`].
    pub(crate) async fn failed(&mut self, error: S3Error) -> Result<(), S3Error> {
        if !self.retry.retries(&error) {
            return Err(error);
        }
        self.failures += 1;
        if !self.retry.allows_another(self.failures) {
            return Err(error);
        }
        if let Retry::Background { stop } = &self.retry
            && stop.is_stopped()
        {
            return Err(S3Error::Stopped);
        }
        let wait = self.retry.delay(self.failures, self.base);
        if let Some(deadline) = self.retry.deadline()
            && Instant::now() + wait >= deadline
        {
            return Err(error);
        }
        self.log(&error);
        match &self.retry {
            Retry::Foreground { .. } => {
                sleep(wait).await;
                Ok(())
            }
            Retry::Background { stop } => tokio::select! {
                () = sleep(wait) => Ok(()),
                () = stop.stopped() => Err(S3Error::Stopped),
            },
        }
    }

    fn log(&self, error: &S3Error) {
        let failures = self.failures;
        let (status, code, request_id) = (error.http_status(), error.code(), error.request_id());
        let cause = error.causes();
        let cause = cause.as_deref();
        if error.is_clock_skew() {
            error!(
                failures,
                request_id,
                "the store rejects the request time; check the system clock, trying again"
            );
        } else if self.retry.warns(failures) {
            warn!(
                failures,
                status,
                code,
                request_id,
                cause,
                error = %error,
                "store request failed, trying again"
            );
        } else {
            debug!(
                failures,
                status,
                code,
                request_id,
                cause,
                error = %error,
                "store request failed, trying again"
            );
        }
    }
}

/// The longest wait after `failures` failed attempts: `base`, doubled for
/// each failure before the last, and `cap` at most.
fn delay_bound(failures: u32, base: Duration, cap: Duration) -> Duration {
    let doublings = failures.saturating_sub(1).min(30);
    base.saturating_mul(1 << doublings).min(cap)
}

/// A random time in `0..=bound`.
fn jitter(bound: Duration) -> Duration {
    let mut bytes = [0; 8];
    if fill_random(&mut bytes).is_err() {
        return bound;
    }
    let fraction = u128::from(u64::from_le_bytes(bytes));
    let nanos = bound.as_nanos() * fraction / u128::from(u64::MAX);
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn ms(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    #[test]
    fn the_longest_wait_doubles_up_to_the_cap() {
        let bounds: Vec<_> = (1..=8)
            .map(|failures| delay_bound(failures, BASE_DELAY, FOREGROUND_CAP))
            .collect();
        assert_eq!(
            bounds,
            [
                ms(100),
                ms(200),
                ms(400),
                ms(800),
                ms(1600),
                ms(3200),
                ms(5000),
                ms(5000)
            ]
        );
    }

    #[test]
    fn no_failure_count_overflows_the_wait() {
        for failures in [0, 1, 2, 31, 32, 33, 64, u32::MAX] {
            let bound = delay_bound(failures, BASE_DELAY, BACKGROUND_CAP);
            assert!(bound >= BASE_DELAY && bound <= BACKGROUND_CAP, "{failures}");
        }
        assert_eq!(
            delay_bound(40, Duration::MAX, BACKGROUND_CAP),
            BACKGROUND_CAP
        );
    }

    #[test]
    fn the_wait_is_a_random_time_below_the_bound() {
        let bound = ms(400);
        let samples: Vec<_> = (0..500).map(|_| jitter(bound)).collect();
        assert!(samples.iter().all(|wait| *wait <= bound));
        let (low, high) = (samples.iter().min().unwrap(), samples.iter().max().unwrap());
        assert!(*low < ms(100), "{low:?}");
        assert!(*high > ms(300), "{high:?}");
    }

    #[test]
    fn an_empty_bound_gives_no_wait() {
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn a_policy_waits_within_its_own_cap() {
        let foreground = Retry::within(Duration::from_secs(60));
        let background = Retry::background();
        for _ in 0..200 {
            assert!(foreground.delay(1, BASE_DELAY) <= ms(100));
            assert!(foreground.delay(20, BASE_DELAY) <= ms(5000));
            assert!(background.delay(20, BASE_DELAY) <= ms(60_000));
        }
        let longest = (0..200)
            .map(|_| background.delay(20, BASE_DELAY))
            .max()
            .unwrap();
        assert!(longest > ms(5000), "{longest:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_timeout_too_long_for_the_clock_gives_a_far_deadline() {
        for timeout in [Duration::MAX, Duration::from_secs(u64::MAX)] {
            let retry = Retry::within(timeout);
            assert_eq!(
                retry.deadline(),
                Some(Instant::now() + FAR_FUTURE),
                "{timeout:?}"
            );
            let attempts = Attempts::new(retry, BASE_DELAY);
            assert_eq!(attempts.attempt(async { Ok(5) }).await.unwrap(), 5);
        }
        let year = Duration::from_secs(365 * 24 * 3600);
        assert_eq!(Retry::within(year).deadline(), Some(Instant::now() + year));
    }

    fn busy() -> S3Error {
        S3Error::status(503, Some("SlowDown"), None)
    }

    fn denied() -> S3Error {
        S3Error::status(403, Some("AccessDenied"), None)
    }

    async fn failing_attempt(attempts: &mut Attempts, error: S3Error) -> Result<(), S3Error> {
        let failure = attempts
            .attempt(async { Err::<(), _>(error) })
            .await
            .unwrap_err();
        attempts.failed(failure).await
    }

    #[tokio::test(start_paused = true)]
    async fn a_foreground_call_fails_with_its_fifth_failure() {
        let mut attempts = Attempts::new(Retry::within(Duration::from_secs(600)), BASE_DELAY);
        for failure in 1..FOREGROUND_ATTEMPTS {
            failing_attempt(&mut attempts, busy()).await.unwrap();
            assert_eq!(attempts.failures(), failure);
        }
        let error = failing_attempt(&mut attempts, busy()).await.unwrap_err();
        assert_eq!(error.code(), Some("SlowDown"));
        assert_eq!(attempts.failures(), FOREGROUND_ATTEMPTS);
    }

    #[tokio::test(start_paused = true)]
    async fn the_waits_of_a_foreground_call_stay_within_the_bounds() {
        let began = Instant::now();
        let mut attempts = Attempts::new(Retry::within(Duration::from_secs(600)), BASE_DELAY);
        for _ in 1..FOREGROUND_ATTEMPTS {
            failing_attempt(&mut attempts, busy()).await.unwrap();
        }
        // 100 + 200 + 400 + 800 ms at most
        assert!(began.elapsed() <= ms(1500), "{:?}", began.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn an_error_trying_again_cannot_fix_ends_the_call_at_once() {
        let began = Instant::now();
        let mut attempts = Attempts::new(Retry::background(), BASE_DELAY);
        let error = failing_attempt(&mut attempts, denied()).await.unwrap_err();
        assert_eq!(error.code(), Some("AccessDenied"));
        assert_eq!(attempts.failures(), 0);
        assert_eq!(began.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_background_call_never_runs_out_of_attempts() {
        let mut attempts = Attempts::new(Retry::background(), BASE_DELAY);
        for _ in 0..40 {
            failing_attempt(&mut attempts, busy()).await.unwrap();
        }
        assert_eq!(attempts.failures(), 40);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_that_would_end_past_the_deadline_ends_the_call_with_the_last_error() {
        let began = Instant::now();
        let mut attempts = Attempts::new(Retry::within(ms(30)), Duration::from_secs(10));
        let mut result = Ok(());
        while result.is_ok() {
            result = failing_attempt(&mut attempts, busy()).await;
        }
        assert_eq!(result.unwrap_err().code(), Some("SlowDown"));
        assert!(began.elapsed() <= ms(30), "{:?}", began.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_still_running_at_the_deadline_is_dropped() {
        let began = Instant::now();
        let attempts = Attempts::new(Retry::within(ms(250)), BASE_DELAY);
        let result = attempts
            .attempt(async {
                sleep(Duration::from_secs(3600)).await;
                Ok(())
            })
            .await;
        assert!(
            matches!(result, Err(S3Error::DeadlineExceeded)),
            "{result:?}"
        );
        assert_eq!(began.elapsed(), ms(250));
    }

    #[tokio::test(start_paused = true)]
    async fn no_attempt_starts_after_the_deadline() {
        let attempts = Attempts::new(
            Retry::Foreground {
                deadline: Instant::now(),
            },
            BASE_DELAY,
        );
        let started = std::cell::Cell::new(false);
        let result = attempts
            .attempt(async {
                started.set(true);
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(S3Error::DeadlineExceeded)));
        assert!(!started.get());
    }

    #[tokio::test(start_paused = true)]
    async fn a_background_attempt_has_no_deadline() {
        let attempts = Attempts::new(Retry::background(), BASE_DELAY);
        let result = attempts
            .attempt(async {
                sleep(Duration::from_secs(36_000)).await;
                Ok(5)
            })
            .await;
        assert_eq!(result.unwrap(), 5);
    }

    #[test]
    fn a_background_call_warns_about_each_failure_after_the_third() {
        let warns: Vec<_> = (1..=6)
            .map(|failures| Retry::background().warns(failures))
            .collect();
        assert_eq!(warns, [false, false, false, true, true, true]);
        let foreground = Retry::within(Duration::from_secs(60));
        assert!((1..=6).all(|failures| !foreground.warns(failures)));
    }

    fn skewed() -> S3Error {
        S3Error::status(403, Some("RequestTimeTooSkewed"), None)
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejected_clock_is_retried_by_a_background_call_only() {
        let mut background = Attempts::new(Retry::background(), BASE_DELAY);
        failing_attempt(&mut background, skewed()).await.unwrap();
        assert_eq!(background.failures(), 1);

        let mut foreground = Attempts::new(Retry::within(Duration::from_secs(60)), BASE_DELAY);
        let error = failing_attempt(&mut foreground, skewed())
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some("RequestTimeTooSkewed"));
        assert_eq!(foreground.failures(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn no_attempt_starts_once_the_call_is_stopped() {
        let stop = Stop::new();
        let attempts = Attempts::new(Retry::until(&stop), BASE_DELAY);
        stop.stop();
        let started = std::cell::Cell::new(false);
        let result = attempts
            .attempt(async {
                started.set(true);
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(S3Error::Stopped)), "{result:?}");
        assert!(!started.get());
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_ends_the_wait_between_attempts() {
        let stop = Stop::new();
        let began = Instant::now();
        let mut attempts = Attempts::new(Retry::until(&stop), Duration::from_secs(3600));
        let waiting = tokio::spawn(async move { failing_attempt(&mut attempts, busy()).await });
        // The task runs up to its wait, which a stop at once cuts short.
        tokio::task::yield_now().await;
        stop.stop();
        let result = waiting.await.unwrap();
        assert!(matches!(result, Err(S3Error::Stopped)), "{result:?}");
        assert_eq!(began.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_lets_an_attempt_under_way_finish() {
        let stop = Stop::new();
        let began = Instant::now();
        let attempts = Attempts::new(Retry::until(&stop), BASE_DELAY);
        let (begun, has_begun) = tokio::sync::oneshot::channel();
        let running = tokio::spawn(async move {
            attempts
                .attempt(async {
                    begun.send(()).unwrap();
                    sleep(Duration::from_secs(5)).await;
                    Ok(5)
                })
                .await
        });
        has_begun.await.unwrap();
        stop.stop();
        assert_eq!(running.await.unwrap().unwrap(), 5);
        assert_eq!(began.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_that_fails_after_the_stop_ends_the_call_as_stopped() {
        let stop = Stop::new();
        let began = Instant::now();
        let mut attempts = Attempts::new(Retry::until(&stop), BASE_DELAY);
        let failure = attempts
            .attempt(async {
                stop.stop();
                sleep(Duration::from_secs(1)).await;
                Err::<(), _>(busy())
            })
            .await
            .unwrap_err();
        assert!(matches!(
            attempts.failed(failure).await,
            Err(S3Error::Stopped)
        ));
        assert_eq!(began.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stopped_call_still_reports_an_error_trying_again_cannot_fix() {
        let stop = Stop::new();
        let mut attempts = Attempts::new(Retry::until(&stop), BASE_DELAY);
        stop.stop();
        let error = attempts.failed(denied()).await.unwrap_err();
        assert_eq!(error.code(), Some("AccessDenied"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_reaches_every_call_that_holds_it() {
        let stop = Stop::new();
        let first = Retry::until(&stop);
        let second = Retry::until(&stop);
        let other = Retry::until(&Stop::new());
        stop.clone().stop();
        for (retry, stopped) in [(first, true), (second, true), (other, false)] {
            let attempts = Attempts::new(retry, BASE_DELAY);
            let result = attempts.attempt(async { Ok(()) }).await;
            assert_eq!(result.is_err(), stopped);
        }
    }
}
