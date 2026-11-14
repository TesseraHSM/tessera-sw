// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! X.509 certificate chain validation.
//!
//! Validates an externally-provided X.509 certificate chain one
//! certificate at a time, suitable for memory-constrained `no_std`
//! environments. [`ChainValidator`] borrows its inputs; [`validate_chain`]
//! borrows adjacent DER views in one DMA allocation without issuer copies.
//!
//! ## Supported algorithms
//!
//! | Signature       | Curve  |
//! |-----------------|--------|
//! | ECDSA with SHA-256/384/512 | P-256/P-384/P-521 (all combinations) |
//! | RSA PKCS#1 v1.5 / PSS with SHA-256/384/512 | 2048/3072/4096 bits |
//! | Pure ML-DSA | 44/65/87 |
//!
//! PSS requires MGF1 with the same digest and trailer field 1. ML-DSA uses
//! an empty context. Composite signatures are not supported.
//! No time validation, CRL, or policy processing.
//!
//! ## Usage
//!
//! ```ignore
//! let mut v = ChainValidator::new(3);
//!
//! // cert[0] = root (self-signed), loaded into buf_a
//! let cert_0 = parse_cert(&buf_a)?;
//! v.step(pal, io, alloc, None, &cert_0).await;             // NeedNext
//!
//! // cert[1] = intermediate, loaded into buf_b
//! let cert_1 = parse_cert(&buf_b)?;
//! v.step(pal, io, alloc, Some(&cert_0), &cert_1).await;    // NeedNext
//!
//! // cert[2] = leaf, loaded into buf_a (overwrites cert[0])
//! let cert_2 = parse_cert(&buf_a)?;
//! v.step(pal, io, alloc, Some(&cert_1), &cert_2).await;    // Valid { ... }
//! ```
//!
//! ## Checks performed (RFC 5280 §6.1, simplified)
//!
//! 1. Signature verification through the PAL (ECDSA, RSA or ML-DSA)
//! 2. Issuer↔subject name chaining (byte-exact DER comparison)
//! 3. AKID↔SKID matching (when both present)
//! 4. BasicConstraints cA=true for intermediate certificates
//! 5. Algorithm-specific KeyUsage restrictions and keyCertSign for CA certificates
//! 6. Rejection of unrecognized critical extensions

mod ecdsa;
mod parse;
mod types;
mod validate;

pub use parse::parse_cert;
pub use types::key_usage;
pub use types::BasicConstraints;
pub use types::CertInfo;
pub use types::EcPubKey;
pub use types::PssParams;
pub use types::PubKey;
pub use types::RsaPubKey;
pub use types::SigAlgo;
pub use types::StepResult;
pub use validate::validate_chain;
pub use validate::validate_issuing_chain;
pub use validate::ChainValidator;
pub use validate::MAX_CERT_DER_LEN;
