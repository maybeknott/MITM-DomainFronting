use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailurePhase {
    Dns,
    TcpConnect,
    TlsServerHello,
    AlpnMismatch,
    HttpStatus,
    FirstByte,
    ThroughputStall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmState {
    Healthy,
    Degraded,
    OpenCircuit,
    HalfOpen,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub timestamp_ms: u64,
    pub phase: Option<FailurePhase>,
    pub latency_ms: Option<u32>,
    pub success: bool,
    pub bytes_per_sec: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ArmStats {
    pub state: ArmState,
    /// Bounded ring buffer of recent samples. A `VecDeque` keeps window
    /// eviction O(1) (`pop_front`) instead of the O(n) shift a `Vec::remove(0)`
    /// incurs on every request once the window is full.
    pub samples: VecDeque<Sample>,
    pub in_flight: u32,
    pub consecutive_failures: u32,
    pub open_until_ms: u64,
    pub last_probe_ms: u64,
}

impl ArmStats {
    fn new(window_limit: usize) -> Self {
        Self {
            state: ArmState::Healthy,
            samples: VecDeque::with_capacity(window_limit),
            in_flight: 0,
            consecutive_failures: 0,
            open_until_ms: 0,
            last_probe_ms: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Selection {
    pub arm_index: usize,
    pub score: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreBreakdown {
    pub success_rate: f64,
    pub confidence_bonus: f64,
    pub latency_penalty: f64,
    pub in_flight_penalty: f64,
    pub circuit_penalty: f64,
}

impl ScoreBreakdown {
    pub fn total(&self) -> f64 {
        self.success_rate + self.confidence_bonus
            - self.latency_penalty
            - self.in_flight_penalty
            - self.circuit_penalty
    }

    pub fn render(&self) -> String {
        format!(
            "success={:.3} conf={:.3} latency=-{:.3} inflight=-{:.3} circuit=-{:.3} score={:.3}",
            self.success_rate,
            self.confidence_bonus,
            self.latency_penalty,
            self.in_flight_penalty,
            self.circuit_penalty,
            self.total()
        )
    }
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn circuit_backoff_ms(
    circuit_base_ms: u64,
    arm_index: usize,
    consecutive_failures: u32,
    now_ms: u64,
) -> u64 {
    let multiplier = 1_u64 << consecutive_failures.min(6);
    let base = circuit_base_ms.saturating_mul(multiplier);
    let seed = now_ms ^ ((arm_index as u64) << 32) ^ ((consecutive_failures as u64) << 16);
    let mixed = splitmix64(seed);
    // Spread retries across arms/time without external RNG or test flakiness.
    // Percent jitter in [75, 125] (±25% band).
    let jitter_pct = 75_u64 + (mixed % 51);
    base.saturating_mul(jitter_pct).saturating_div(100).max(1)
}

pub struct PathScheduler {
    arms: Vec<ArmStats>,
    window_limit: usize,
    circuit_base_ms: u64,
    total_samples: u64,
}

impl PathScheduler {
    pub fn new(arm_count: usize, window_limit: usize, circuit_base_ms: u64) -> Self {
        let bounded_window = window_limit.max(1);
        Self {
            arms: (0..arm_count)
                .map(|_| ArmStats::new(bounded_window))
                .collect(),
            window_limit: bounded_window,
            circuit_base_ms,
            total_samples: 0,
        }
    }

    pub fn begin_request(&mut self, _now_ms: u64) -> Option<Selection> {
        let selection = self.select_foreground()?;
        self.arms[selection.arm_index].in_flight =
            self.arms[selection.arm_index].in_flight.saturating_add(1);
        Some(selection)
    }

    pub fn finish_request(
        &mut self,
        arm_index: usize,
        now_ms: u64,
        success: bool,
        phase: Option<FailurePhase>,
        latency_ms: Option<u32>,
        bytes_per_sec: Option<u32>,
    ) {
        let Some(arm) = self.arms.get_mut(arm_index) else {
            return;
        };
        arm.in_flight = arm.in_flight.saturating_sub(1);
        if arm.samples.len() == self.window_limit {
            arm.samples.pop_front();
        }
        arm.samples.push_back(Sample {
            timestamp_ms: now_ms,
            phase,
            latency_ms,
            success,
            bytes_per_sec,
        });
        self.total_samples = self.total_samples.saturating_add(1);

        if success {
            arm.consecutive_failures = 0;
            arm.state = ArmState::Healthy;
            return;
        }

        arm.consecutive_failures = arm.consecutive_failures.saturating_add(1);
        arm.state = if arm.consecutive_failures >= 3 {
            let backoff_ms = circuit_backoff_ms(
                self.circuit_base_ms,
                arm_index,
                arm.consecutive_failures,
                now_ms,
            );
            arm.open_until_ms = now_ms.saturating_add(backoff_ms);
            ArmState::OpenCircuit
        } else {
            ArmState::Degraded
        };
    }

    pub fn select_foreground(&self) -> Option<Selection> {
        let mut best: Option<Selection> = None;
        for (idx, arm) in self.arms.iter().enumerate() {
            // Foreground selection must not route around the circuit breaker.
            // Recovery happens through a single half-open probe only.
            if arm.state == ArmState::OpenCircuit {
                continue;
            }
            if arm.state == ArmState::HalfOpen {
                continue;
            }
            let breakdown = self.score_arm(arm);
            let score = breakdown.total();
            let selection = Selection {
                arm_index: idx,
                score,
                reason: format!(
                    "state={:?} samples={} {}",
                    arm.state,
                    arm.samples.len(),
                    breakdown.render()
                ),
            };
            if best
                .as_ref()
                .is_none_or(|current| selection.score > current.score)
            {
                best = Some(selection);
            }
        }
        best
    }

    pub fn select_probe(&mut self, now_ms: u64) -> Option<Selection> {
        let mut candidate: Option<(usize, u64)> = None;
        for (idx, arm) in self.arms.iter().enumerate() {
            if arm.state != ArmState::OpenCircuit || now_ms < arm.open_until_ms {
                continue;
            }
            if candidate.is_none_or(|(_, last_probe)| arm.last_probe_ms < last_probe) {
                candidate = Some((idx, arm.last_probe_ms));
            }
        }
        let (idx, _) = candidate?;
        let arm = &mut self.arms[idx];
        arm.state = ArmState::HalfOpen;
        arm.last_probe_ms = now_ms;
        Some(Selection {
            arm_index: idx,
            score: 0.0,
            reason: "half-open background probe".to_string(),
        })
    }

    pub fn arm(&self, arm_index: usize) -> Option<&ArmStats> {
        self.arms.get(arm_index)
    }

    pub fn score_arm(&self, arm: &ArmStats) -> ScoreBreakdown {
        if arm.samples.is_empty() {
            let in_flight_penalty = arm.in_flight as f64 * 0.05;
            return ScoreBreakdown {
                success_rate: 1.0,
                confidence_bonus: 0.0,
                latency_penalty: 0.0,
                in_flight_penalty,
                circuit_penalty: 0.0,
            };
        }

        let sample_count = arm.samples.len() as f64;
        let success_count = arm.samples.iter().filter(|sample| sample.success).count() as f64;
        let success_rate = success_count / sample_count;
        // Only divide by the number of samples that actually carry a latency
        // reading. Failures often have `latency_ms=None` (e.g. DNS/TCP failures)
        // and including those untimed failures in the divisor would dilute the
        // latency penalty toward zero precisely when the arm is flaking.
        let mut timed_count: f64 = 0.0;
        let mut timed_sum_ms: f64 = 0.0;
        for sample in &arm.samples {
            if let Some(latency_ms) = sample.latency_ms {
                timed_count += 1.0;
                timed_sum_ms += f64::from(latency_ms);
            }
        }
        let avg_latency = if timed_count > 0.0 {
            timed_sum_ms / timed_count
        } else {
            0.0
        };
        let latency_penalty = (avg_latency / 1000.0).min(0.5);
        let in_flight_penalty = arm.in_flight as f64 * 0.05;
        let circuit_penalty = match arm.state {
            ArmState::Healthy => 0.0,
            ArmState::Degraded => 0.2,
            ArmState::HalfOpen => 0.4,
            ArmState::OpenCircuit => 0.8,
        };
        let confidence_bonus = if self.total_samples > 0 {
            ((self.total_samples as f64).ln() / sample_count).sqrt() * 0.1
        } else {
            0.0
        };

        ScoreBreakdown {
            success_rate,
            confidence_bonus,
            latency_penalty,
            in_flight_penalty,
            circuit_penalty,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avoids_open_circuit_for_foreground_traffic() {
        let mut scheduler = PathScheduler::new(2, 8, 1_000);
        for i in 0..3 {
            scheduler.finish_request(
                0,
                100 + i,
                false,
                Some(FailurePhase::TcpConnect),
                None,
                None,
            );
        }
        let selected = scheduler.begin_request(500).expect("healthy arm remains");
        assert_eq!(selected.arm_index, 1);
        assert_eq!(scheduler.arm(0).expect("arm").state, ArmState::OpenCircuit);
    }

    #[test]
    fn expired_open_circuit_is_not_admitted_to_foreground_without_probe() {
        // Single-arm scheduler whose only path trips its circuit. Once the
        // backoff elapses, the arm must STILL be withheld from foreground
        // selection: recovery has to go through a half-open probe, not a
        // full-traffic flood the instant the timer expires.
        let mut scheduler = PathScheduler::new(1, 8, 100);
        for i in 0..3 {
            scheduler.finish_request(
                0,
                100 + i,
                false,
                Some(FailurePhase::TcpConnect),
                None,
                None,
            );
        }
        assert_eq!(scheduler.arm(0).expect("arm").state, ArmState::OpenCircuit);
        let open_until = scheduler.arm(0).expect("arm").open_until_ms;
        let after_expiry = open_until.saturating_add(10_000);

        assert!(
            scheduler.begin_request(after_expiry).is_none(),
            "expired-but-unprobed open circuit must not serve foreground traffic"
        );

        let probe = scheduler
            .select_probe(after_expiry)
            .expect("probe admitted");
        assert_eq!(probe.arm_index, 0);
        assert_eq!(scheduler.arm(0).expect("arm").state, ArmState::HalfOpen);

        scheduler.finish_request(0, after_expiry + 5, true, None, Some(50), Some(5_000));
        assert_eq!(scheduler.arm(0).expect("arm").state, ArmState::Healthy);
        assert!(scheduler.begin_request(after_expiry + 10).is_some());
    }

    #[test]
    fn half_open_probe_recovers_path() {
        let mut scheduler = PathScheduler::new(1, 8, 100);
        for i in 0..3 {
            scheduler.finish_request(
                0,
                100 + i,
                false,
                Some(FailurePhase::TlsServerHello),
                None,
                None,
            );
        }
        let probe = scheduler.select_probe(1_000).expect("probe");
        assert_eq!(probe.arm_index, 0);
        assert_eq!(scheduler.arm(0).expect("arm").state, ArmState::HalfOpen);
        scheduler.finish_request(0, 1_010, true, None, Some(80), Some(10_000));
        assert_eq!(scheduler.arm(0).expect("arm").state, ArmState::Healthy);
    }

    #[test]
    fn selection_reason_includes_score_breakdown() {
        let mut scheduler = PathScheduler::new(1, 8, 1_000);
        scheduler.finish_request(0, 100, true, None, Some(50), None);
        let selection = scheduler.begin_request(200).expect("selection");
        assert!(selection.reason.contains("success="));
        assert!(selection.reason.contains("conf="));
        assert!(selection.reason.contains("latency=-"));
        assert!(selection.reason.contains("inflight=-"));
        assert!(selection.reason.contains("circuit=-"));
        assert!(selection.reason.contains("score="));
    }

    #[test]
    fn sample_window_is_bounded_and_evicts_oldest() {
        let window = 4;
        let mut scheduler = PathScheduler::new(1, window, 100);
        for i in 0..20 {
            scheduler.finish_request(0, 100 + i, true, None, Some(i as u32), None);
        }
        let arm = scheduler.arm(0).expect("arm");
        assert_eq!(arm.samples.len(), window, "window must stay bounded");
        // Oldest entries are evicted, so the retained latencies are the last four.
        let latencies: Vec<u32> = arm.samples.iter().filter_map(|s| s.latency_ms).collect();
        assert_eq!(latencies, vec![16, 17, 18, 19]);
    }

    #[test]
    fn tracks_in_flight_lifecycle() {
        let mut scheduler = PathScheduler::new(1, 4, 100);
        let selected = scheduler.begin_request(10).expect("selection");
        assert_eq!(selected.arm_index, 0);
        assert_eq!(scheduler.arm(0).expect("arm").in_flight, 1);
        scheduler.finish_request(0, 20, true, None, Some(20), None);
        assert_eq!(scheduler.arm(0).expect("arm").in_flight, 0);
    }

    #[test]
    fn latency_penalty_ignores_untimed_failures() {
        // Two arms with identical success rates and identical untimed failures,
        // but different timed success latencies. The fast arm must outrank the
        // slow arm by the full (clamped) latency penalty gap; untimed failures
        // must not dilute the computed average latency toward zero.
        let mut scheduler = PathScheduler::new(2, 32, 1_000);

        // 10 successes + 10 untimed failures on each arm.
        for i in 0..10_u64 {
            scheduler.finish_request(0, 10 + i, true, None, Some(900), None);
            scheduler.finish_request(1, 10 + i, true, None, Some(10), None);
        }
        for i in 0..10_u64 {
            scheduler.finish_request(0, 100 + i, false, Some(FailurePhase::Dns), None, None);
            scheduler.finish_request(1, 100 + i, false, Some(FailurePhase::Dns), None, None);
        }

        let slow = scheduler.score_arm(scheduler.arm(0).expect("arm0")).total();
        let fast = scheduler.score_arm(scheduler.arm(1).expect("arm1")).total();
        assert!(
            fast > slow,
            "fast arm must outrank slow arm (fast={} slow={})",
            fast,
            slow
        );
    }

    #[test]
    fn circuit_backoff_jitter_stays_within_band_and_is_deterministic() {
        let base = 1_000_u64;
        let failures = 3_u32;
        let now_ms = 123_456_u64;
        let multiplier = 1_u64 << failures.min(6);
        let unjittered = base * multiplier;

        let a = circuit_backoff_ms(base, 0, failures, now_ms);
        let b = circuit_backoff_ms(base, 0, failures, now_ms);
        assert_eq!(a, b, "same inputs must yield deterministic backoff");
        assert!(
            a >= unjittered * 75 / 100 && a <= unjittered * 125 / 100,
            "backoff must stay within ±25% jitter band"
        );
    }

    #[test]
    fn circuit_backoff_jitter_decorrelates_across_arms() {
        let base = 1_000_u64;
        let failures = 4_u32;
        let now_ms = 999_u64;
        let a0 = circuit_backoff_ms(base, 0, failures, now_ms);
        let a1 = circuit_backoff_ms(base, 1, failures, now_ms);
        assert_ne!(a0, a1, "different arms should not share identical backoff");
    }
}
