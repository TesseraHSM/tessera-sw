// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! Open the same socket-backed HSM partition from multiple threads on Windows or Linux.
//!
//! Run with `cargo run -p tsra_api_sock_get_api_rev --features sock -- [ENDPOINT] [THREADS]`.
//! Defaults are `tcp://127.0.0.1:1234` and four threads on both platforms.
//! Unix socket paths and Linux `vsock://CID:PORT` endpoints are also supported.
//! Each worker opens its own API partition handle and socket connection. The
//! example only queries metadata; it does not initialize or reset the partition.

mod example {
    const DEFAULT_ENDPOINT: &str = "tcp://127.0.0.1:1234";
    const DEFAULT_THREADS: usize = 4;

    #[derive(Debug, PartialEq, Eq)]
    struct Options {
        endpoint: String,
        threads: usize,
    }

    fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
        let endpoint = args.next().unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned());
        if endpoint.is_empty() {
            return Err("endpoint must not be empty".to_owned());
        }
        let threads = args
            .next()
            .map(|value| value.parse::<usize>())
            .transpose()
            .map_err(|error| format!("invalid thread count: {error}"))?
            .unwrap_or(DEFAULT_THREADS);
        if threads == 0 {
            return Err("thread count must be greater than zero".to_owned());
        }
        if args.next().is_some() {
            return Err("usage: tsra_api_sock_get_api_rev [ENDPOINT] [THREADS]".to_owned());
        }
        Ok(Options { endpoint, threads })
    }

    fn run_workers(
        threads: usize,
        operation: impl Fn(usize) -> Result<(), String> + Sync,
    ) -> Result<(), String> {
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            let mut result = Ok(());
            for worker_id in 1..=threads {
                let operation = &operation;
                match std::thread::Builder::new()
                    .name(format!("api-socket-{worker_id}"))
                    .spawn_scoped(scope, move || operation(worker_id))
                {
                    Ok(worker) => workers.push((worker_id, worker)),
                    Err(error) => {
                        result = Err(format!("failed to start worker {worker_id}: {error}"));
                        break;
                    }
                }
            }
            for (worker_id, worker) in workers {
                let worker_result = match worker.join() {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(format!("worker {worker_id} failed: {error}")),
                    Err(_) => Err(format!("worker {worker_id} panicked")),
                };
                if result.is_ok() {
                    result = worker_result;
                }
            }
            result
        })
    }

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        use tsra_api::HsmPartitionManager;

        let options = parse_args(std::env::args().skip(1))?;
        std::env::set_var("TSRA_DDI_SOCK", &options.endpoint);

        let info = HsmPartitionManager::partition_info_list()
            .into_iter()
            .find(|info| info.path == options.endpoint)
            .ok_or("the socket endpoint was not discovered")?;
        let rev = info
            .api_rev_range
            .ok_or("failed to query the API revision; check the endpoint and socket server")?
            .max();

        run_workers(options.threads, |worker_id| {
            let partition = HsmPartitionManager::open_partition(&info.path, rev)
                .map_err(|error| error.to_string())?;
            let range = partition.api_rev_range();
            let min = range.min();
            let max = range.max();
            println!(
                "Worker {worker_id}: opened {}: min={}.{} max={}.{}",
                partition.path(),
                min.major,
                min.minor,
                max.major,
                max.minor
            );
            Ok(())
        })?;

        println!(
            "All {} workers opened the same partition at {}",
            options.threads, info.path
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use std::collections::HashSet;
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;

        use parking_lot::Mutex;

        use super::*;

        #[test]
        fn default_options() {
            assert_eq!(
                parse_args(std::iter::empty()).expect("default options"),
                Options {
                    endpoint: DEFAULT_ENDPOINT.to_owned(),
                    threads: DEFAULT_THREADS,
                }
            );
        }

        #[test]
        fn explicit_options() {
            for endpoint in [
                "tcp://127.0.0.1:1234",
                "tcp://[::1]:1234",
                "vsock://7:1234",
                "/tmp/tsra-ddi.sock",
            ] {
                assert_eq!(
                    parse_args([endpoint, "8"].into_iter().map(str::to_owned))
                        .expect("explicit options"),
                    Options {
                        endpoint: endpoint.to_owned(),
                        threads: 8,
                    }
                );
            }
        }

        #[test]
        fn rejects_invalid_options() {
            for args in [
                vec![""],
                vec![DEFAULT_ENDPOINT, "0"],
                vec![DEFAULT_ENDPOINT, "-1"],
                vec![DEFAULT_ENDPOINT, "invalid"],
                vec![DEFAULT_ENDPOINT, "4", "extra"],
            ] {
                assert!(parse_args(args.into_iter().map(str::to_owned)).is_err());
            }
        }

        #[test]
        fn runs_operation_on_distinct_threads() {
            let thread_ids = Mutex::new(HashSet::new());
            run_workers(4, |_| {
                thread_ids.lock().insert(std::thread::current().id());
                Ok(())
            })
            .expect("workers complete");
            assert_eq!(thread_ids.into_inner().len(), 4);
        }

        #[test]
        fn joins_all_workers_after_an_error() {
            let completed = AtomicUsize::new(0);
            let result = run_workers(4, |worker_id| {
                completed.fetch_add(1, Ordering::SeqCst);
                if worker_id == 2 {
                    Err("connection failed".to_owned())
                } else {
                    Ok(())
                }
            });
            assert_eq!(result, Err("worker 2 failed: connection failed".to_owned()));
            assert_eq!(completed.load(Ordering::SeqCst), 4);
        }

        #[test]
        fn reports_worker_panics() {
            let result = run_workers(1, |_| panic!("worker failure"));
            assert_eq!(result, Err("worker 1 panicked".to_owned()));
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    example::run()
}
