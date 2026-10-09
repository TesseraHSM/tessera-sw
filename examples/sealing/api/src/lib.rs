// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Example sealing API: security-domain building blocks on top of the
//! public `tsra_api` surface.
//!
//! A reusable API for authoring sealing root services. It provides both the
//! building blocks and the [`SecurityDomain::create`] flow that composes them:
//!
//! * [`SealingSession`] — open and factory-reset a partition, rotate the
//!   Crypto-Officer PSK, and hand back a live CO session.
//! * [`SecurityDomainEnv`] — serves the complete policy and anchor
//!   certificate thumbprints for the domain's lifetime.
//! * [`SecurityDomainStore`] — atomically persists [`PartitionState`] and
//!   [`SecurityDomainState`] recovery records in one save.
//! * [`mint_sealing_key`] — the HSM-side sealing key.
//! * [`SecurityDomain::create`] — drives a factory-reset partition through the full
//!   security-domain provisioning flow, taking externally supplied
//!   receiver certificates and evidence, plus a POTA signing callback.
//!   The signer supplies a complete root-first list of DER certificates.
//!   Returns [`RemoteBackup`] with the remote backup and owned [`Evidence`].
//! * [`SecurityDomain::restore_local`] — restores the partition masking key and
//!   security domain with the original seed and POTA signer, then atomically
//!   saves refreshed local recovery records.
//! * [`load_local_recovery`] — validates complete saved recovery material before
//!   opening or resetting a device.
//! * [`SecurityDomain::restore_remote`] — restores the partition's local MK,
//!   then restores the SD using its remote backup and original receiver key.
//!   Supports separate SATA-endorsed external-SA HPKE certificates, or the
//!   existing attested sender path for legacy recovery. Does not consume or
//!   fall back to a local SD backup.
//! * [`load_partition_recovery`] — validates partition-only recovery material
//!   for remote SD recovery.
//! * [`SecurityDomain::prepare_remote_restore`] — restores the partition's
//!   local MK and creates a fresh attested receiver, without restoring an SD.
//! * [`reseal_remote_backup`] — opens and reseals a backup inside the
//!   authority HSM, binding source and destination evidence to the SD policy.
//! * [`SecurityDomain::restore_resealed`] — consumes the authority's
//!   [`ResealedBackup`] and saves refreshed local recovery. The authority's
//!   report attests its own policy; the application verifies that policy,
//!   while firmware enforces the domain's SATA/SAPOTA authorization.
//! * [`SecurityDomain::prepare_peer`] — finalizes a new peer using the full
//!   existing policy and a fresh partition-local masking key, without creating
//!   another SD. Its POTA signing callback may contact an external authority.
//! * [`SecurityDomain::create_peer_backup`] — exports the live SD to an
//!   attested receiver, with application-supplied sender evidence.
//! * [`SecurityDomain::restore_peer`] — imports the receiver-bound peer backup
//!   and atomically saves destination-local recovery records.
//!
//! Peer operations contain no HTTP, JSON or demo trust policy. Applications
//! authenticate peers, validate evidence and retain [`PreparedPeer`] locally.
//!
//! The application (e.g. `root_svc`) owns the trust keys and supplies the
//! receiver credentials and POTA signing callback, so trust keys stay
//! outside the device-facing flow.

pub mod env;
pub mod error;
pub mod evidence;
pub mod hsm;
pub mod peer;
pub mod remote;
pub mod sd;
pub mod session;
pub mod store;

pub use env::SecurityDomainEnv;
pub use error::Error;
pub use evidence::Evidence;
pub use hsm::device_cert_chain;
pub use hsm::mint_sealing_key;
pub use hsm::sealing_props;
pub use hsm::SealingKey;
pub use hsm::RAW_PUB_LEN;
pub use peer::PeerBackup;
pub use peer::PreparedPeer;
pub use remote::reseal_remote_backup;
pub use remote::PreparedRemoteRestore;
pub use remote::ResealedBackup;
pub use sd::RemoteBackup;
pub use sd::RemoteRecovery;
pub use sd::SecurityDomain;
pub use session::SealingSession;
pub use store::load_local_recovery;
pub use store::load_partition_recovery;
pub use store::PartitionState;
pub use store::SecurityDomainState;
pub use store::SecurityDomainStore;
