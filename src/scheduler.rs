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
    pub samples: Vec<Sample>,
    pub in_flight: u32,
    pub consecutive_failures: u32,
    pub open_until_ms: u64,
    pub last_probe_ms: u64,
}

impl ArmStats {
    fn new(window_limit: usize) -> Self {
        Self {
            state: ArmState::Healthy,
            samples: Vec::with_capacity(window_limit),
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

    pub fn begin_request(&mut self, now_ms: u64) -> Option<Selection> {
        let selection = self.select_foreground(now_ms)?;
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
            arm.samples.remove(0);
        }
        arm.samples.push(Sample {
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
            let multiplier = 1_u64 << arm.consecutive_failures.min(6);
            arm.open_until_ms =
                now_ms.saturating_add(self.circuit_base_ms.saturating_mul(multiplier));
            ArmState::OpenCircuit
        } else {
            ArmState::Degraded
        };
    }

    pub fn select_foreground(&self, now_ms: u64) -> Option<Selection> {
        let mut best: Option<Selection> = None;
        for (idx, arm) in self.arms.iter().enumerate() {
            if arm.state == ArmState::OpenCircuit && now_ms < arm.open_until_ms {
                continue;
            }
            if arm.state == ArmState::HalfOpen {
                continue;
            }
            let score = self.score_arm(arm);
            let selection = Selection {
                arm_index: idx,
                score,
                reason: format!("state={:?} samples={}", arm.state, arm.samples.len()),
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

    fn score_arm(&self, arm: &ArmStats) -> f64 {
        if arm.samples.is_empty() {
            return 1.0 - (arm.in_flight as f64 * 0.05);
        }

        let sample_count = arm.samples.len() as f64;
        let success_count = arm.samples.iter().filter(|sample| sample.success).count() as f64;
        let success_rate = success_count / sample_count;
        let avg_latency = arm
            .samples
            .iter()
            .filter_map(|sample| sample.latency_ms)
            .map(f64::from)
            .sum::<f64>()
            / sample_count.max(1.0);
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

        success_rate + confidence_bonus - latency_penalty - in_flight_penalty - circuit_penalty
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
    fn tracks_in_flight_lifecycle() {
        let mut scheduler = PathScheduler::new(1, 4, 100);
        let selected = scheduler.begin_request(10).expect("selection");
        assert_eq!(selected.arm_index, 0);
        assert_eq!(scheduler.arm(0).expect("arm").in_flight, 1);
        scheduler.finish_request(0, 20, true, None, Some(20), None);
        assert_eq!(scheduler.arm(0).expect("arm").in_flight, 0);
    }
}
