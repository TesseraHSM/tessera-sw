// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use std::io;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tsra_ddi_sock_proto::ProtoError;
use tsra_ddi_sock_proto::ResponseFrame;

use super::Connection;
use super::SocketHsm;

async fn write_response(
    stream: &mut UnixStream,
    response: &ResponseFrame,
) -> Result<(), ProtoError> {
    let body = response.encode()?;
    stream.write_u32_le(body.len() as u32).await?;
    stream.write_all(&body).await?;
    Ok(())
}

async fn serve_connection(mut stream: UnixStream, hsm: Arc<SocketHsm>) -> Result<(), String> {
    let connection = Connection::new(hsm);
    loop {
        let Some(request) = super::read_request_with_timeout(&mut stream).await? else {
            return Ok(());
        };
        let response =
            match tokio::time::timeout(super::CONNECTION_READ_TIMEOUT, connection.execute(request))
                .await
            {
                Ok(result) => result?,
                Err(_elapsed) => return Ok(()),
            };
        tokio::time::timeout(
            super::CONNECTION_READ_TIMEOUT,
            write_response(&mut stream, &response),
        )
        .await
        .map_err(|_elapsed| "failed to write DDI response: timed out".to_string())?
        .map_err(|error| format!("failed to write DDI response: {error}"))?;
    }
}

async fn run_server(listener: UnixListener, hsm: Arc<SocketHsm>) -> Result<(), String> {
    loop {
        let (stream, _peer) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept Unix socket connection: {error}"))?;
        let hsm = Arc::clone(&hsm);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, hsm).await {
                eprintln!("Unix socket client failed: {error}");
            }
        });
    }
}

pub(super) fn run(path: &str) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to remove stale Unix socket at {path}: {error}"
            ));
        }
    }
    let path = path.to_owned();
    super::run_with_hsm(|hsm| async move {
        let listener = UnixListener::bind(&path)
            .map_err(|error| format!("failed to bind Unix listener at {path}: {error}"))?;
        super::init_partition(&hsm).await?;
        println!("TSRA DDI server listening on unix://{path}; partition 10");
        run_server(listener, hsm).await
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tsra_ddi_interface::Ddi;
    use tsra_ddi_interface::DdiDev;
    use tsra_ddi_sock::DdiSock;
    use tsra_ddi_tbor_types::TborGetCertChainInfoReq;

    use super::*;

    fn socket_path() -> std::path::PathBuf {
        let unique = format!(
            "ddi-sock-server-test-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("monotonic clock")
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn roundtrips_a_request_over_a_unix_socket() {
        let _guard = crate::test_partition_lock();
        let hsm = crate::test_hsm();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let path = socket_path();
        runtime.block_on(async {
            let listener = UnixListener::bind(&path).expect("listener");
            let endpoint = path.to_str().expect("utf-8 path").to_owned();
            let serving = tokio::spawn(run_server(listener, Arc::clone(&hsm)));
            let client = tokio::task::spawn_blocking(move || {
                let device = DdiSock::default()
                    .open_dev(&endpoint)
                    .expect("unix socket device");
                device
                    .exec_op_tbor(&TborGetCertChainInfoReq::new(0), None, &mut None)
                    .expect("cert chain info roundtrip");
            });
            tokio::time::timeout(Duration::from_secs(30), client)
                .await
                .expect("client completes")
                .expect("client task");
            serving.abort();
        });
        std::fs::remove_file(&path).ok();
    }
}
