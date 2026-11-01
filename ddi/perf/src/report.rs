// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Result output: console, TSV rows, markdown tables and comparisons.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::time::SystemTime;

use crate::bench::RunResult;
use crate::RunArgs;

const TSV_HEADER: &str = "unix_time\tlabel\top\tthreads\tpayload\tkeys\tseconds\tops\trps\tmean_us\tstddev_us\tmin_us\tp50_us\tp90_us\tp99_us\tmax_us\terrors";

/// Print a run's results.
pub(crate) fn print_run(result: &RunResult) {
    println!(
        "{:<24} {:>3} {:>8} {:>9} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>6}",
        "op",
        "thr",
        "ops",
        "rps",
        "mean_us",
        "p50_us",
        "p90_us",
        "p99_us",
        "min_us",
        "max_us",
        "errors"
    );
    for o in &result.ops {
        let l = o.latency.unwrap_or_default();
        println!(
            "{:<24} {:>3} {:>8} {:>9.1} {:>10.1} {:>10.1} {:>10.1} {:>10.1} {:>10.1} {:>10.1} {:>6}",
            o.op.name(),
            result.threads,
            o.count,
            o.rps,
            l.mean,
            l.p50,
            l.p90,
            l.p99,
            l.min,
            l.max,
            o.errors
        );
        if let Some(e) = &o.first_error {
            println!("    first error: {e}");
        }
    }
    if result.ops.len() > 1 {
        let total: u64 = result.ops.iter().map(|o| o.count).sum();
        println!(
            "{:<24} {:>3} {:>8} {:>9.1}",
            "total",
            result.threads,
            total,
            total as f64 / result.seconds as f64
        );
    }
}

/// Append a run's rows to a TSV file, writing the header to a new file.
pub(crate) fn append_tsv(path: &Path, args: &RunArgs, result: &RunResult) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let new = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len()
        == 0;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = String::new();
    if new {
        out.push_str(TSV_HEADER);
        out.push('\n');
    }
    for o in &result.ops {
        let l = o.latency.unwrap_or_default();
        let _ = writeln!(
            out,
            "{now}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{}",
            args.label,
            o.op.name(),
            result.threads,
            o.op.payload(args),
            args.keys,
            result.seconds,
            o.count,
            o.rps,
            l.mean,
            l.stddev,
            l.min,
            l.p50,
            l.p90,
            l.p99,
            l.max,
            o.errors
        );
    }
    file.write_all(out.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

/// A markdown table of suite results.
pub(crate) fn suite_markdown(args: &RunArgs, results: &[RunResult]) -> String {
    let mut s = String::new();
    if !args.label.is_empty() {
        let _ = writeln!(s, "Label: `{}`\n", args.label);
    }
    let _ = writeln!(
        s,
        "{}s measured per run after {}s warm-up; {} keys per key type, {} messages per thread.\n",
        args.test_seconds, args.stabilize_seconds, args.keys, args.messages
    );
    s.push_str("| Operation | Payload | Threads | Ops | RPS | Mean µs | p50 µs | p90 µs | p99 µs | Max µs | Errors |\n");
    s.push_str("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for r in results {
        for o in &r.ops {
            let l = o.latency.unwrap_or_default();
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {} |",
                o.op.name(),
                o.op.payload(args),
                r.threads,
                o.count,
                o.rps,
                l.mean,
                l.p50,
                l.p90,
                l.p99,
                l.max,
                o.errors
            );
        }
    }
    s
}

/// One TSV row, keyed for comparison.
struct Row {
    label: String,
    rps: f64,
    p50: f64,
    p99: f64,
}

/// Rows keyed by `(op, threads, payload)`, in file order; a later row
/// replaces an earlier one with the same key.
type Rows = Vec<((String, usize, String), Row)>;

fn read_tsv(path: &Path) -> Result<Rows, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_tsv(&text, &path.display().to_string())
}

/// Parse `--tsv` output read from `source` (named in errors).
fn parse_tsv(text: &str, source: &str) -> Result<Rows, String> {
    let mut lines = text.lines();
    let header: Vec<&str> = lines
        .next()
        .ok_or_else(|| format!("{source} is empty"))?
        .split('\t')
        .collect();
    let col = |name: &str| {
        header
            .iter()
            .position(|h| *h == name)
            .ok_or_else(|| format!("{source}: no {name} column"))
    };
    let (c_label, c_op, c_thr, c_payload) =
        (col("label")?, col("op")?, col("threads")?, col("payload")?);
    let (c_rps, c_p50, c_p99) = (col("rps")?, col("p50_us")?, col("p99_us")?);

    let mut rows: Rows = Vec::new();
    let mut index = BTreeMap::new();
    for (n, line) in lines.enumerate() {
        let f: Vec<&str> = line.split('\t').collect();
        let get = |c: usize| {
            f.get(c)
                .copied()
                .ok_or_else(|| format!("{source} line {}: too few columns", n + 2))
        };
        let num = |c: usize| -> Result<f64, String> {
            get(c)?
                .parse::<f64>()
                .map_err(|e| format!("{source} line {}: {e}", n + 2))
        };
        let threads = get(c_thr)?
            .parse::<usize>()
            .map_err(|e| format!("{source} line {}: {e}", n + 2))?;
        let key = (get(c_op)?.to_owned(), threads, get(c_payload)?.to_owned());
        let row = Row {
            label: get(c_label)?.to_owned(),
            rps: num(c_rps)?,
            p50: num(c_p50)?,
            p99: num(c_p99)?,
        };
        match index.get(&key) {
            Some(&i) => rows[i] = (key, row),
            None => {
                index.insert(key.clone(), rows.len());
                rows.push((key, row));
            }
        }
    }
    Ok(rows)
}

fn delta(base: f64, cand: f64) -> String {
    if base == 0.0 {
        "-".into()
    } else {
        format!("{:+.1}%", (cand - base) / base * 100.0)
    }
}

/// Compare the rows two TSV files have in common.
pub(crate) fn compare(
    baseline: &Path,
    candidate: &Path,
    markdown: Option<&Path>,
) -> Result<(), String> {
    let base = read_tsv(baseline)?;
    let cand = read_tsv(candidate)?;
    let label = |rows: &Rows, path: &Path| {
        rows.first()
            .map(|(_, r)| r.label.clone())
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| path.display().to_string())
    };

    let mut s = String::new();
    let _ = writeln!(s, "Baseline: `{}`  ", label(&base, baseline));
    let _ = writeln!(s, "Candidate: `{}`\n", label(&cand, candidate));
    s.push_str("| Operation | Payload | Threads | RPS before | RPS after | Δ RPS | p50 µs before | p50 µs after | Δ p50 | p99 µs before | p99 µs after |\n");
    s.push_str("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for (key, b) in &base {
        let Some((_, c)) = cand.iter().find(|(k, _)| k == key) else {
            continue;
        };
        let _ = writeln!(
            s,
            "| {} | {} | {} | {:.1} | {:.1} | {} | {:.1} | {:.1} | {} | {:.1} | {:.1} |",
            key.0,
            key.2,
            key.1,
            b.rps,
            c.rps,
            delta(b.rps, c.rps),
            b.p50,
            c.p50,
            delta(b.p50, c.p50),
            b.p99,
            c.p99
        );
    }
    print!("{s}");
    if let Some(path) = markdown {
        std::fs::write(path, &s).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::append_tsv;
    use super::parse_tsv;
    use super::TSV_HEADER;
    use crate::bench::RunResult;
    use crate::RunArgs;

    #[test]
    fn later_rows_replace_earlier_rows_with_the_same_key() {
        let text = format!(
            "{TSV_HEADER}\n\
             1\tfw\ttbor-get-api-rev\t1\t-\t8\t10\t100\t10.0\t1\t0\t1\t2\t3\t4\t5\t0\n\
             2\tfw\ttbor-ecc-sign-p256\t1\t32B digest\t8\t10\t50\t5.0\t1\t0\t1\t20\t30\t40\t50\t0\n\
             3\tfw\ttbor-get-api-rev\t1\t-\t8\t10\t200\t20.0\t1\t0\t1\t7\t8\t9\t10\t0\n"
        );
        let rows = parse_tsv(&text, "t.tsv").expect("valid TSV");
        assert_eq!(rows.len(), 2);
        let ((op, threads, payload), row) = &rows[0];
        assert_eq!(
            (op.as_str(), *threads, payload.as_str()),
            ("tbor-get-api-rev", 1, "-")
        );
        assert_eq!((row.rps, row.p50, row.p99), (20.0, 7.0, 9.0));
        assert_eq!(rows[1].0 .0, "tbor-ecc-sign-p256");
    }

    #[test]
    fn malformed_tsv_is_an_error() {
        assert!(parse_tsv("", "t.tsv").is_err());
        assert!(parse_tsv("label\top\tthreads\tpayload\n", "t.tsv").is_err());
        assert!(parse_tsv(&format!("{TSV_HEADER}\n1\tfw\ttbor-get-api-rev\n"), "t.tsv").is_err());
        assert!(parse_tsv(
            &format!("{TSV_HEADER}\n1\tfw\tx\tmany\t-\t8\t10\t1\t1\t1\t1\t1\t1\t1\t1\t1\t0\n"),
            "t.tsv"
        )
        .is_err());
    }

    #[test]
    fn empty_existing_file_gets_a_header() {
        let path =
            std::env::temp_dir().join(format!("tsra-ddi-perf-empty-{}.tsv", std::process::id()));
        std::fs::write(&path, []).expect("create empty TSV");
        let args = RunArgs {
            device: 0,
            stabilize_seconds: 0,
            test_seconds: 1,
            keys: 1,
            messages: 1,
            cbc_len: 16,
            verify_all: false,
            max_samples: 1,
            tsv: None,
            label: String::new(),
            quiet: true,
        };
        let result = RunResult {
            threads: 1,
            seconds: 1,
            ops: Vec::new(),
        };
        append_tsv(&path, &args, &result).expect("append TSV header");
        let text = std::fs::read_to_string(&path).expect("read TSV");
        assert_eq!(text, format!("{TSV_HEADER}\n"));
        std::fs::remove_file(path).expect("remove TSV");
    }
}
