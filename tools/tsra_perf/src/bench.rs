// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Multi-threaded load generation and latency statistics.

use std::sync::Barrier;
use std::sync::OnceLock;
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
    /// Summarize latencies given in nanoseconds; `None` when empty.
    fn of(mut nanos: Vec<u64>) -> Option<Self> {
        if nanos.is_empty() {
            return None;
        }
        nanos.sort_unstable();
        let us = |ns: u64| ns as f64 / 1000.0;
        let n = nanos.len();
        let pct = |p: usize| us(nanos[((n - 1) * p).div_ceil(100)]);
        let mean = nanos.iter().map(|&ns| us(ns)).sum::<f64>() / n as f64;
        let var = nanos
            .iter()
            .map(|&ns| us(ns) - mean)
            .fold(0.0, |acc, d| d.mul_add(d, acc))
            / n as f64;
        Some(Self {
            mean,
            stddev: var.sqrt(),
            min: us(nanos[0]),
            p50: pct(50),
            p90: pct(90),
            p99: pct(99),
            max: us(nanos[n - 1]),
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
    errors: u64,
    first_error: Option<String>,
}

/// Run `mix` on `threads` workers and collect the measured window.
pub(crate) fn run(
    env: &Env,
    args: &RunArgs,
    threads: usize,
    mix: &[(OpKind, u32)],
) -> Result<RunResult, String> {
    let kinds: Vec<OpKind> = mix.iter().map(|m| m.0).collect();
    let cumulative: Vec<u32> = mix
        .iter()
        .scan(0u32, |acc, m| {
            *acc += m.1;
            Some(*acc)
        })
        .collect();
    let total_weight = *cumulative.last().ok_or("empty operation mix")?;

    let stabilize = Duration::from_secs(args.stabilize_seconds);
    let window = Duration::from_secs(args.test_seconds);
    let ready = Barrier::new(threads + 1);
    let start: OnceLock<Instant> = OnceLock::new();
    let started = Barrier::new(threads + 1);

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
        let handles: Vec<_> = (0..threads)
            .map(|tid| {
                let (kinds, cumulative) = (&kinds, &cumulative);
                let (ready, started, start) = (&ready, &started, &start);
                s.spawn(move || {
                    // A panic here must not strand the others at the barrier.
                    let worker = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        Worker::new(env, args, tid, kinds)
                    }))
                    .unwrap_or_else(|_| Err(format!("thread {tid}: opening the device panicked")));
                    ready.wait();
                    started.wait();
                    let mut worker = worker?;
                    let t0 = *start.get().expect("set before the start barrier");
                    let measure_from = t0 + stabilize;
                    let measure_to = measure_from + window;
                    let stop = measure_to + stabilize;

                    let mut records: Vec<Record> =
                        kinds.iter().map(|_| Record::default()).collect();
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
                            rec.count += 1;
                            if rec.nanos.len() < args.max_samples {
                                rec.nanos.push(dt.as_nanos() as u64);
                            }
                        }
                    }
                    Ok(records)
                })
            })
            .collect();

        // Start everyone together once all workers are ready.
        ready.wait();
        let _ = start.set(Instant::now());
        started.wait();
        if !args.quiet {
            progress(stabilize, window);
        }
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err("worker thread panicked".into()))
            })
            .collect()
    });

    let mut merged: Vec<Record> = kinds.iter().map(|_| Record::default()).collect();
    for records in per_thread {
        for (m, r) in merged.iter_mut().zip(records?) {
            m.count += r.count;
            m.nanos.extend(r.nanos);
            m.errors += r.errors;
            if m.first_error.is_none() {
                m.first_error = r.first_error;
            }
        }
    }

    let ops = kinds
        .iter()
        .zip(merged)
        .map(|(&op, r)| OpResult {
            op,
            count: r.count,
            rps: r.count as f64 / window.as_secs_f64(),
            latency: Summary::of(r.nanos),
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
