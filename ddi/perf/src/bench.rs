// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Multi-threaded load generation and latency statistics.

use std::thread;
use std::time::Duration;
use std::time::Instant;

use rand::RngExt;

use crate::ops::OpKind;
use crate::ops::Worker;
use crate::setup::Env;
use crate::RunArgs;

/// Latency statistics in microseconds.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Summary {
    pub(crate) mean: f64,
    pub(crate) stddev: f64,
    pub(crate) min: f64,
    pub(crate) p50: f64,
    pub(crate) p90: f64,
    pub(crate) p99: f64,
    pub(crate) max: f64,
}

impl Summary {
    /// Summarize the sample's percentiles and the full window's aggregates.
    fn of(
        mut samples: Vec<(u64, f64)>,
        count: u64,
        mean_ns: f64,
        m2_ns: f64,
        min_ns: u64,
        max_ns: u64,
    ) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        samples.sort_unstable_by_key(|&(ns, _)| ns);
        let us = |ns: u64| ns as f64 / 1000.0;
        let total_weight: f64 = samples.iter().map(|&(_, weight)| weight).sum();
        let pct = |p: usize| {
            let target = total_weight * p as f64 / 100.0;
            let mut weight = 0.0;
            let ns = samples
                .iter()
                .find_map(|&(ns, sample_weight)| {
                    weight += sample_weight;
                    (weight > target).then_some(ns)
                })
                .unwrap_or_else(|| samples.last().expect("non-empty sample").0);
            us(ns)
        };
        Some(Self {
            mean: mean_ns / 1000.0,
            stddev: (m2_ns / count as f64).sqrt() / 1000.0,
            min: us(min_ns),
            p50: pct(50),
            p90: pct(90),
            p99: pct(99),
            max: us(max_ns),
        })
    }
}

/// Results for one operation of a run.
#[derive(Debug)]
pub(crate) struct OpResult {
    pub(crate) op: OpKind,
    /// Requests completed inside the measured window.
    pub(crate) count: u64,
    pub(crate) rps: f64,
    pub(crate) latency: Option<Summary>,
    /// Failed requests in any phase.
    pub(crate) errors: u64,
    pub(crate) first_error: Option<String>,
}

/// Results of one run.
#[derive(Debug)]
pub(crate) struct RunResult {
    pub(crate) threads: usize,
    pub(crate) seconds: u64,
    pub(crate) ops: Vec<OpResult>,
}

impl RunResult {
    /// Fail if any request failed.
    pub(crate) fn check(&self) -> Result<(), String> {
        match self.ops.iter().find(|o| o.errors > 0) {
            Some(o) => Err(format!(
                "{}: {} failed requests, first: {}",
                o.op.name(),
                o.errors,
                o.first_error.as_deref().unwrap_or("?")
            )),
            None => Ok(()),
        }
    }
}

/// Per-thread, per-operation record.
#[derive(Default)]
struct Record {
    count: u64,
    nanos: Vec<u64>,
    weighted_nanos: Vec<(u64, f64)>,
    mean_ns: f64,
    m2_ns: f64,
    min_ns: u64,
    max_ns: u64,
    errors: u64,
    first_error: Option<String>,
}

impl Record {
    fn observe(&mut self, ns: u64, max_samples: usize, rng: &mut impl rand::RngExt) {
        self.count += 1;
        let delta = ns as f64 - self.mean_ns;
        self.mean_ns += delta / self.count as f64;
        let delta2 = ns as f64 - self.mean_ns;
        self.m2_ns = delta.mul_add(delta2, self.m2_ns);
        if self.count == 1 {
            self.min_ns = ns;
            self.max_ns = ns;
        } else {
            self.min_ns = self.min_ns.min(ns);
            self.max_ns = self.max_ns.max(ns);
        }

        if self.nanos.len() < max_samples {
            self.nanos.push(ns);
        } else if max_samples != 0 {
            let slot = rng.random_range(0..self.count);
            if slot < max_samples as u64 {
                self.nanos[slot as usize] = ns;
            }
        }
    }

    fn merge(&mut self, other: Self) {
        if other.count != 0 {
            if self.count == 0 {
                self.mean_ns = other.mean_ns;
                self.m2_ns = other.m2_ns;
                self.min_ns = other.min_ns;
                self.max_ns = other.max_ns;
            } else {
                let count = self.count + other.count;
                let delta = other.mean_ns - self.mean_ns;
                self.mean_ns += delta * other.count as f64 / count as f64;
                self.m2_ns += other.m2_ns
                    + delta * delta * self.count as f64 * other.count as f64 / count as f64;
                self.min_ns = self.min_ns.min(other.min_ns);
                self.max_ns = self.max_ns.max(other.max_ns);
            }
        }
        self.count += other.count;
        if other.weighted_nanos.is_empty() {
            if !other.nanos.is_empty() {
                let weight = other.count as f64 / other.nanos.len() as f64;
                self.weighted_nanos
                    .extend(other.nanos.into_iter().map(|ns| (ns, weight)));
            }
        } else {
            self.weighted_nanos.extend(other.weighted_nanos);
        }
        self.errors += other.errors;
        if self.first_error.is_none() {
            self.first_error = other.first_error;
        }
    }
}

#[derive(Clone, Copy)]
enum StartupOutcome {
    Start(Instant),
    Abort,
}

/// Run `mix` on `threads` workers and collect the measured window.
pub(crate) fn run(
    env: &Env,
    args: &RunArgs,
    threads: usize,
    mix: &[(OpKind, u32)],
) -> Result<RunResult, String> {
    let kinds: Vec<OpKind> = mix.iter().map(|m| m.0).collect();
    let cumulative = cumulative_weights(mix)?;
    let total_weight = *cumulative.last().ok_or("empty operation mix")?;

    let stabilize = Duration::from_secs(args.stabilize_seconds);
    let window = Duration::from_secs(args.test_seconds);
    let names: Vec<String> = kinds.iter().map(|k| k.name()).collect();
    if !args.quiet {
        println!(
            "running {} on {threads} thread(s): {}s warm-up, {}s measured, {}s cool-down",
            names.join("+"),
            args.stabilize_seconds,
            args.test_seconds,
            args.stabilize_seconds
        );
    }

    let per_thread: Vec<Result<Vec<Record>, String>> = thread::scope(|s| {
        let mut handles = Vec::with_capacity(threads);
        let mut start_senders = Vec::with_capacity(threads);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        for tid in 0..threads {
            let (kinds, cumulative) = (&kinds, &cumulative);
            let ready_tx = ready_tx.clone();
            let (start_tx, start_rx) = std::sync::mpsc::channel();
            let handle = thread::Builder::new().spawn_scoped(s, move || {
                let worker = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Worker::new(env, args, tid, kinds)
                }))
                .unwrap_or_else(|_| Err(format!("thread {tid}: opening the device panicked")));
                ready_tx
                    .send(())
                    .map_err(|_| format!("thread {tid}: startup coordinator exited"))?;
                drop(ready_tx);
                let t0 = match start_rx.recv() {
                    Ok(StartupOutcome::Start(start)) => start,
                    Ok(StartupOutcome::Abort) | Err(_) => {
                        return Err(format!("thread {tid}: startup aborted"));
                    }
                };
                let mut worker = worker?;
                let measure_from = t0 + stabilize;
                let measure_to = measure_from + window;
                let stop = measure_to + stabilize;

                let mut records: Vec<Record> = kinds.iter().map(|_| Record::default()).collect();
                let mut rng = rand::rng();
                while Instant::now() < stop {
                    let pick = rng.random_range(0..total_weight);
                    let i = cumulative.partition_point(|&c| c <= pick);
                    let (dt, result) = worker.exec(kinds[i], args.verify_all);
                    let done = Instant::now();
                    let rec = &mut records[i];
                    if let Err(e) = result {
                        rec.errors += 1;
                        rec.first_error.get_or_insert(e);
                    } else if done >= measure_from && done < measure_to {
                        rec.observe(dt.as_nanos() as u64, args.max_samples, &mut rng);
                    }
                }
                Ok(records)
            });
            match handle {
                Ok(handle) => {
                    handles.push(handle);
                    start_senders.push(start_tx);
                }
                Err(e) => {
                    for sender in start_senders {
                        let _ = sender.send(StartupOutcome::Abort);
                    }
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(format!("failed to spawn worker thread {tid}: {e}"));
                }
            }
        }

        drop(ready_tx);
        for _ in 0..threads {
            if ready_rx.recv().is_err() {
                for sender in &start_senders {
                    let _ = sender.send(StartupOutcome::Abort);
                }
                for handle in handles {
                    let _ = handle.join();
                }
                return Err("worker exited before startup".into());
            }
        }
        let start = Instant::now();
        let mut failed_start = false;
        for sender in &start_senders {
            failed_start |= sender.send(StartupOutcome::Start(start)).is_err();
        }
        if failed_start {
            for sender in &start_senders {
                let _ = sender.send(StartupOutcome::Abort);
            }
            for handle in handles {
                let _ = handle.join();
            }
            return Err("failed to release worker threads".into());
        }
        if !args.quiet {
            progress(stabilize, window);
        }
        Ok(handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err("worker thread panicked".into()))
            })
            .collect())
    })?;

    let mut merged: Vec<Record> = kinds.iter().map(|_| Record::default()).collect();
    for records in per_thread {
        for (m, r) in merged.iter_mut().zip(records?) {
            m.merge(r);
        }
    }

    let ops = kinds
        .iter()
        .zip(merged)
        .map(|(&op, r)| OpResult {
            op,
            count: r.count,
            rps: r.count as f64 / window.as_secs_f64(),
            latency: Summary::of(
                r.weighted_nanos,
                r.count,
                r.mean_ns,
                r.m2_ns,
                r.min_ns,
                r.max_ns,
            ),
            errors: r.errors,
            first_error: r.first_error,
        })
        .collect();
    Ok(RunResult {
        threads,
        seconds: args.test_seconds,
        ops,
    })
}

/// Running totals of the mix's weights, which pick each request's
/// operation; fails if they do not fit in a `u32`.
pub(crate) fn cumulative_weights(mix: &[(OpKind, u32)]) -> Result<Vec<u32>, String> {
    let mut total = 0u32;
    mix.iter()
        .map(|&(_, weight)| {
            total = total
                .checked_add(weight)
                .ok_or_else(|| String::from("operation weights add up to more than u32::MAX"))?;
            Ok(total)
        })
        .collect()
}

/// Show the phases on stdout while the workers run.
fn progress(stabilize: Duration, window: Duration) {
    use std::io::Write;

    for (phase, len) in [
        ("warm-up", stabilize),
        ("measure", window),
        ("cool-down", stabilize),
    ] {
        print!("  {phase} ");
        let _ = std::io::stdout().flush();
        let secs = len.as_secs();
        for _ in 0..secs {
            thread::sleep(Duration::from_secs(1));
            print!(".");
            let _ = std::io::stdout().flush();
        }
        thread::sleep(len - Duration::from_secs(secs));
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::cumulative_weights;
    use super::Record;
    use super::Summary;
    use crate::ops::OpKind;

    #[test]
    fn summary_of_known_latencies() {
        let s = Summary::of(
            (1..=100).map(|us| (us * 1000, 1.0)).collect(),
            100,
            50_500.0,
            83_325_000_000.0,
            1_000,
            100_000,
        )
        .expect("non-empty");
        assert_eq!((s.min, s.max, s.mean), (1.0, 100.0, 50.5));
        assert_eq!((s.p50, s.p90, s.p99), (51.0, 91.0, 100.0));
        assert!((s.stddev - 28.866_070_047_7).abs() < 0.000_1);
        assert!(Summary::of(Vec::new(), 0, 0.0, 0.0, 0, 0).is_none());
    }

    #[test]
    fn latency_sample_and_aggregates_cover_the_full_window() {
        let mut record = Record::default();
        let mut rng = rand::rng();
        for ns in 1..=1000 {
            record.observe(ns, 10, &mut rng);
        }
        assert_eq!(record.nanos.len(), 10);
        let summary = Summary::of(
            record.nanos.into_iter().map(|ns| (ns, 100.0)).collect(),
            record.count,
            record.mean_ns,
            record.m2_ns,
            record.min_ns,
            record.max_ns,
        )
        .expect("non-empty sample");
        assert_eq!(summary.mean, 0.5005);
        assert_eq!((summary.min, summary.max), (0.001, 1.0));
        let expected_stddev = (999_999.0_f64 / 12.0).sqrt() / 1000.0;
        assert!((summary.stddev - expected_stddev).abs() < 0.000_001);
    }

    #[test]
    fn merged_latency_samples_are_weighted_by_request_count() {
        let mut merged = Record::default();
        merged.merge(Record {
            count: 1000,
            nanos: vec![1],
            mean_ns: 1.0,
            min_ns: 1,
            max_ns: 1,
            ..Record::default()
        });
        merged.merge(Record {
            count: 10,
            nanos: vec![100_000],
            mean_ns: 100_000.0,
            min_ns: 100_000,
            max_ns: 100_000,
            ..Record::default()
        });

        let summary = Summary::of(
            merged.weighted_nanos,
            merged.count,
            merged.mean_ns,
            merged.m2_ns,
            merged.min_ns,
            merged.max_ns,
        )
        .expect("non-empty sample");
        assert_eq!(summary.p50, 0.001);
        assert_eq!(summary.max, 100.0);
    }

    #[test]
    fn cumulative_weights_reject_overflow() {
        let (a, b) = (OpKind::TborGetApiRev, OpKind::MborGetApiRev);
        assert_eq!(cumulative_weights(&[(a, 3), (b, 1)]), Ok(vec![3, 4]));
        assert!(cumulative_weights(&[(a, u32::MAX), (b, 1)]).is_err());
    }
}
