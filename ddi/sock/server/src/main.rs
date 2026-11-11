// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone TSRA DDI socket server; see the library docs.

use std::io::IsTerminal;

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    if let Err(error) = ddi_sock_server::run(|listening| {
        println!("TSRA DDI server listening on {listening}");
    }) {
        eprintln!("TSRA DDI socket server failed: {error}");
        std::process::exit(1);
    }
}
