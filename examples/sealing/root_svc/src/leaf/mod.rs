// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Named independent security domains, not peer clones. The root retains
//! leaf signers and a local-scoped HSM receiver key for each registration.
//! All enrollment uses the same explicitly unauthenticated loopback demo
//! transport as peer cloning. A name is not an authentication credential.

mod registry;

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Instant;

use jzon::JsonValue;
use tsra_sealing_api::SealingSession;
use tsra_sealing_api::SecurityDomain;
pub(crate) use tsra_sealing_common::leaf_name as validate_name;

use crate::env::SelfContainedEnv;

type RootDomain = SecurityDomain<SelfContainedEnv>;

pub(crate) fn handle(
    domain: &RootDomain,
    session: &SealingSession,
    method: &str,
    path: &str,
    request: &JsonValue,
) -> anyhow::Result<JsonValue> {
    static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
    let context = trace_context(method, path, request);
    let started = Instant::now();
    eprintln!("[root leaf] request={id} {context} phase=start");
    let result = registry::handle(domain, session, method, path, request);
    let status = if result.is_ok() { 200 } else { 400 };
    eprintln!(
        "[root leaf] request={id} {context} phase=complete status={status} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    result
}

fn trace_context(method: &str, path: &str, request: &JsonValue) -> String {
    let (name, route) = path
        .strip_prefix("/v1/leaves/")
        .map(|suffix| suffix.split_once('/').unwrap_or((suffix, "")))
        .unwrap_or((request["name"].as_str().unwrap_or(""), "register"));
    let operation = match (method, route) {
        ("POST", "register") => "register",
        ("GET", "") => "configuration",
        ("POST", "policy") => "policy",
        ("POST", "pta-cert") => "pta-enrollment",
        ("POST", "instances") => "authorize-instance",
        ("GET", op) if op.starts_with("instances/") => "instance-status",
        ("POST", "catalog") => "publish-catalog",
        ("GET", "catalog") => "fetch-catalog",
        ("GET", "receiver") => "receiver-evidence",
        ("GET", "recovery") => "recovery-check",
        ("POST", "reseal") => "reseal",
        ("POST", "backup") => "store-backup",
        _ => "unsupported",
    };
    let instance = route.strip_prefix("instances/").or_else(|| {
        matches!(route, "pta-cert" | "reseal" | "instances")
            .then(|| request["instance"].as_str().unwrap_or("primary"))
    });
    let safe_name = |value: &str| {
        if validate_name(value).is_ok() {
            value.to_owned()
        } else {
            "<invalid>".to_owned()
        }
    };
    format!(
        "leaf={} instance={} operation={operation}",
        safe_name(name),
        instance.map(safe_name).unwrap_or_else(|| "-".to_owned())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_metadata_excludes_payloads_and_invalid_identifiers() {
        let request = jzon::object! {
            name: "orders", instance: "replica-02",
            report: "private-report", policy: "private-policy",
            pok_remote_backup: "private-backup",
        };
        assert_eq!(
            trace_context("POST", "/v1/leaves/orders/reseal", &request),
            "leaf=orders instance=replica-02 operation=reseal"
        );
        assert_eq!(
            trace_context(
                "GET",
                "/v1/leaves/orders/instances/replica-02",
                &JsonValue::Null
            ),
            "leaf=orders instance=replica-02 operation=instance-status"
        );
        assert_eq!(
            trace_context(
                "POST",
                "/v1/leaves/orders\nforged/reseal",
                &jzon::object! { instance: "secret\nforged" }
            ),
            "leaf=<invalid> instance=<invalid> operation=reseal"
        );
        assert_eq!(
            trace_context(
                "GET",
                "/v1/leaves/orders/report-secret?token=secret",
                &request
            ),
            "leaf=orders instance=- operation=unsupported"
        );
    }

    #[test]
    fn names_are_safe_single_path_components() {
        for valid in ["orders", "a-1_b", &"a".repeat(64)] {
            assert!(validate_name(valid).is_ok());
        }
        for invalid in [
            "",
            ".",
            "..",
            "../orders",
            "a/b",
            "a\\b",
            "a%2fb",
            "Orders",
            "a b",
            &"a".repeat(65),
        ] {
            assert!(validate_name(invalid).is_err(), "{invalid}");
        }
    }
}
