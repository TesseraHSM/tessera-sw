// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `tsra_perf` — throughput and latency of Tessera HSM commands on the
//! regular HSM path, modeled on `mcr_perf`.
//!
//! A run spawns `--threads` workers that issue requests back to back
//! through a warm-up period, a measured window and a cool-down period, all
//! aligned to one start time so every thread is loaded for the whole
//! window. Only requests that complete inside the window count, and only
//! the device call is timed.
//!
//! Inputs vary per request: keyed operations rotate through `--keys`
//! distinct keys and each thread through `--messages` distinct messages,
//! so nothing can be cached or specialized across requests. Before any
//! timing, every selected operation runs against each key and is checked
//! against a host reference (OpenSSL through `tsra_crypto`); a device that
//! returns wrong results fails the run instead of producing numbers.
//! `--verify-all` checks every timed response as well.

mod bench;
mod ops;
mod report;
mod setup;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

use crate::ops::OpKind;
use crate::ops::OpWeight;
use crate::setup::Env;

#[derive(Parser)]
#[command(version, about = "Tessera HSM command throughput and latency")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one weighted mix of operations.
    Perf(PerfArgs),
    /// Run each operation alone at each thread count and print a table.
    Suite(SuiteArgs),
    /// Compare two result files written with `--tsv`.
    Compare(CompareArgs),
    /// List the operations.
    List,
}

/// Options shared by `perf` and `suite`.
#[derive(Args, Clone, Debug)]
pub(crate) struct RunArgs {
    /// Device index, as enumerated by the DDI backend.
    #[arg(long, default_value_t = 0)]
    pub(crate) device: usize,

    /// Seconds of load before and after the measured window.
    #[arg(long, default_value_t = 2)]
    pub(crate) stabilize_seconds: u64,

    /// Length of the measured window in seconds.
    #[arg(long, default_value_t = 10)]
    pub(crate) test_seconds: u64,

    /// Distinct keys per key type; requests rotate through them.
    #[arg(long, default_value_t = 8)]
    pub(crate) keys: usize,

    /// Distinct messages per thread; requests rotate through them.
    #[arg(long, default_value_t = 64)]
    pub(crate) messages: usize,

    /// `TestAesGcm` text length in bytes.
    #[arg(long, default_value_t = 2048)]
    pub(crate) gcm_len: usize,

    /// `TestAesGcm` AAD length in bytes.
    #[arg(long, default_value_t = 32)]
    pub(crate) gcm_aad_len: usize,

    /// `AesEncryptDecrypt` (AES-256-CBC) message length in bytes.
    #[arg(long, default_value_t = 1024)]
    pub(crate) cbc_len: usize,

    /// Check every timed response against the host reference too.
    #[arg(long)]
    pub(crate) verify_all: bool,

    /// Latency samples kept per thread and operation.
    #[arg(long, default_value_t = 1_000_000)]
    pub(crate) max_samples: usize,

    /// Append result rows to this TSV file.
    #[arg(long)]
    pub(crate) tsv: Option<PathBuf>,

    /// Label stored with each result row, e.g. the firmware version.
    #[arg(long, default_value = "")]
    pub(crate) label: String,

    /// Suppress progress output.
    #[arg(long)]
    pub(crate) quiet: bool,
}

#[derive(Args)]
struct PerfArgs {
    #[command(flatten)]
    run: RunArgs,

    /// Number of worker threads.
    #[arg(long, default_value_t = 1)]
    threads: usize,

    /// Operation as NAME or NAME=WEIGHT; repeat for a mix (see `list`).
    #[arg(long = "op", required = true)]
    ops: Vec<OpWeight>,
}

#[derive(Args)]
struct SuiteArgs {
    #[command(flatten)]
    run: RunArgs,

    /// Thread counts to run each operation at.
    #[arg(long, value_delimiter = ',', default_value = "1,4")]
    threads: Vec<usize>,

    /// Operations to run [default: the baseline set].
    #[arg(long = "op", value_delimiter = ',')]
    ops: Vec<OpKind>,

    /// Also write the summary table to this markdown file.
    #[arg(long)]
    markdown: Option<PathBuf>,
}

#[derive(Args)]
struct CompareArgs {
    /// Baseline results (TSV from `--tsv`).
    baseline: PathBuf,

    /// Candidate results (TSV from `--tsv`).
    candidate: PathBuf,

    /// Also write the comparison to this markdown file.
    #[arg(long)]
    markdown: Option<PathBuf>,
}

/// Operations `suite` runs by default.
const BASELINE_OPS: &[OpKind] = &[
    OpKind::MborGetApiRev,
    OpKind::TborGetApiRev,
    OpKind::EccSignP256,
    OpKind::EccSignP384,
    OpKind::RsaSign2k,
    OpKind::RsaSign2kCrt,
    OpKind::AesGcmEncrypt,
    OpKind::AesCbcEncrypt,
];

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Perf(args) => perf(args),
        Command::Suite(args) => suite(args),
        Command::Compare(args) => {
            report::compare(&args.baseline, &args.candidate, args.markdown.as_deref())
        }
        Command::List => {
            for op in OpKind::value_variants() {
                println!("{}", op.name());
            }
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn check_args(run: &RunArgs, threads: &[usize]) -> Result<(), String> {
    if run.keys == 0 || run.messages == 0 {
        return Err("--keys and --messages must be at least 1".into());
    }
    if run.test_seconds == 0 {
        return Err("--test-seconds must be at least 1".into());
    }
    if threads.is_empty() || threads.contains(&0) {
        return Err("thread counts must be at least 1".into());
    }
    if run.cbc_len == 0 || !run.cbc_len.is_multiple_of(16) {
        return Err("--cbc-len must be a non-zero multiple of 16".into());
    }
    Ok(())
}

fn perf(args: PerfArgs) -> Result<(), String> {
    check_args(&args.run, &[args.threads])?;
    let mix: Vec<(OpKind, u32)> = args.ops.iter().map(|w| (w.op, w.weight)).collect();
    let kinds: BTreeSet<OpKind> = mix.iter().map(|m| m.0).collect();

    let env = Env::new(&args.run, &kinds)?;
    let result = bench::run(&env, &args.run, args.threads, &mix);
    env.close();
    let result = result?;

    report::print_run(&result);
    if let Some(path) = &args.run.tsv {
        report::append_tsv(path, &args.run, &result)?;
    }
    result.check()
}

fn suite(args: SuiteArgs) -> Result<(), String> {
    check_args(&args.run, &args.threads)?;
    let ops = if args.ops.is_empty() {
        BASELINE_OPS.to_vec()
    } else {
        args.ops.clone()
    };
    let kinds: BTreeSet<OpKind> = ops.iter().copied().collect();

    let env = Env::new(&args.run, &kinds)?;
    let mut results = Vec::new();
    let mut failure = None;
    'ops: for &op in &ops {
        for &threads in &args.threads {
            let result = match bench::run(&env, &args.run, threads, &[(op, 1)]) {
                Ok(r) => r,
                Err(e) => {
                    failure = Some(e);
                    break 'ops;
                }
            };
            report::print_run(&result);
            if let Some(path) = &args.run.tsv {
                report::append_tsv(path, &args.run, &result)?;
            }
            if let Err(e) = result.check() {
                failure.get_or_insert(e);
            }
            results.push(result);
        }
    }
    env.close();

    let table = report::suite_markdown(&args.run, &results);
    println!();
    print!("{table}");
    if let Some(path) = &args.markdown {
        std::fs::write(path, &table).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    failure.map_or(Ok(()), Err)
}
