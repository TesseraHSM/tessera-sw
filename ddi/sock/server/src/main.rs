// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone TSRA DDI socket server; see the library docs.

fn main() {
    if let Err(error) = ddi_sock_server::run() {
        eprintln!("TSRA DDI socket server failed: {error}");
        std::process::exit(1);
    }
}
