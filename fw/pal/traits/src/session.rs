// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session management trait for the HSM PAL.
//!
//! Defines the [`HsmSessionManager`] trait that PAL implementations use
//! to manage authenticated user sessions within a partition.  Each
//! session is identified by a logical [`HsmSessId`] (slot index 0–7)
//! and is scoped to the IO's bound partition.
//!
//! ## Session storage
//!
//! Sessions are stored as vault keys (`HsmVaultKeyKind::Session`)
//! containing an 88-byte blob: `[api_revision(8) || masking_key(80)]`.
//! The session table maps logical session IDs to physical vault key
//! IDs ([`HsmKeyId`]).
//!
//! ## Session lifecycle
//!
//! ```text
//! session_create(io, api_rev, masking_key, None) → logical HsmSessId
//!   ↓
//! session_state(io, id)   — verify session is active
//!   ↓
//! session_create(io, api_rev, masking_key, Some(id)) — re-key after migration
//!   ↓
//! session_destroy(io, id) — close: delete scoped keys + session key + free slot
//! ```
//!
//! ## Session–key binding
//!
//! Session-scoped vault keys are bound to the session's **physical**
//! vault key ID (not the logical slot index).  When a session is
//! deleted, all keys matching that physical ID are removed first.

use super::*;

/// Lifecycle state of a session.
///
/// Returned by [`HsmSessionManager::session_state`].  The state is
/// derived from the underlying vault entry plus session-table
/// metadata; there is no separate persistent state field.
pub enum HsmSessionState {
    /// The session slot is allocated and the masking key is valid for
    /// the current API revision.  The session may be used.
    Active,

    /// The session slot is allocated, but the API revision recorded in
    /// the masking blob does not match the live one (e.g. after a VM
    /// migration).  The host must call
    /// [`HsmSessionManager::session_create`] with `id =
    /// Some(existing)` to re-key before any further operations.
    NeedsRenegotiation,

    /// The session slot is reserved by an in-flight session
    /// establishment handshake.  Allocated by
    /// [`HsmSessionManager::session_create_pending`] and promoted to
    /// [`Active`](Self::Active) via
    /// [`HsmSessionManager::session_promote`] when the client's
    /// `OpenSessionFinish` message verifies.  No session-encrypted
    /// traffic can flow until promotion succeeds.
    Pending,

    /// The slot is free, the partition does not own such a session, or
    /// the session was destroyed.  Any operation referencing this ID
    /// must fail.
    Invalid,
}

/// Caller role asserted by the session-establishment handshake.
///
/// Roles are determined by the PSK identifier presented in
/// `OpenSessionInit` (`psk_id = 0` → CO, `psk_id = 1` → CU) and pinned
/// for the session lifetime.  The role determines which logical slot
/// range the session occupies and which TBOR commands the session may
/// invoke.  Both roles get the same encrypted channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmSessionRole {
    /// Crypto Officer — administrative role.  Sessions land in
    /// slot 0.
    CryptoOfficer,

    /// Crypto User — regular role.  Sessions land in slots 1..=7.
    CryptoUser,
}

/// Channel profile asserted by the session-establishment handshake.
///
/// Selected by the `session_type` field of `OpenSessionInit`, bound into
/// the handshake transcript and pinned for the session lifetime.  Every
/// session, CO and CU alike, is [`Encrypted`](Self::Encrypted); the byte
/// stays on the wire so future profiles need no format break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HsmSessionType {
    /// Every in-session request and response is AES-256-GCM protected
    /// under the per-direction session transport keys.
    Encrypted = 0,
}

impl HsmSessionType {
    /// Wire-encode this `HsmSessionType` to its `u8` discriminant.
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parse a wire `u8` into a `HsmSessionType`.
    ///
    /// Returns [`HsmError::InvalidSessionType`] for any value other
    /// than `0` (Encrypted).
    #[inline]
    pub const fn from_u8(v: u8) -> HsmResult<Self> {
        match v {
            0 => Ok(Self::Encrypted),
            _ => Err(HsmError::InvalidSessionType),
        }
    }
}

/// Cryptographic suite negotiated by the session-establishment
/// handshake.
///
/// A suite pairs a key-encapsulation mechanism with the signature the
/// HSM uses to authenticate the handshake transcript.  The key
/// schedule (HKDF-SHA-384), the transport AEAD (AES-256-GCM) and the
/// confirmation MAC (HMAC-SHA-384) are common to every suite.
///
/// The suite identifier is carried as a single byte in the
/// `OpenSessionInit` request, bound into the signed transcript, and
/// persisted in the Pending blob so `OpenSessionFinish` can recover it
/// without trusting any client-side state.
///
/// # Wire registry
///
/// | `suite_id` | Variant | KEM | Signature |
/// |---|---|---|---|
/// | `0x01` | [`EcdhP384EcdsaP384`](Self::EcdhP384EcdsaP384) | ephemeral ECDH P-384 | ECDSA P-384 (partition identity) |
/// | `0x02` | [`MlKem1024EcdsaP384`](Self::MlKem1024EcdsaP384) | ML-KEM-1024 | ECDSA P-384 (partition identity) |
///
/// Any other value is rejected by `OpenSessionInit` with
/// [`HsmError::UnsupportedSessionSuite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HsmSessionSuite {
    /// Ephemeral-ephemeral ECDH on P-384.  `pk_init` and `enc` are SEC1
    /// uncompressed points (97 B); the shared secret is the 48 B
    /// big-endian x-coordinate.
    EcdhP384EcdsaP384 = 0x01,

    /// ML-KEM-1024 (FIPS 203).  `pk_init` is the 1568 B encapsulation
    /// key, `enc` the 1568 B ciphertext; the shared secret is 32 B.
    MlKem1024EcdsaP384 = 0x02,
}

impl HsmSessionSuite {
    /// Wire-encode this `HsmSessionSuite` to its `u8` discriminant.
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parse a wire `u8` into a `HsmSessionSuite`.
    ///
    /// Returns [`HsmError::UnsupportedSessionSuite`] for any value
    /// that this firmware build does not implement (including `0x00`).
    #[inline]
    pub const fn from_u8(v: u8) -> HsmResult<Self> {
        match v {
            0x01 => Ok(Self::EcdhP384EcdsaP384),
            0x02 => Ok(Self::MlKem1024EcdsaP384),
            _ => Err(HsmError::UnsupportedSessionSuite),
        }
    }

    /// Length of the initiator's KEM public key (`pk_init`).
    #[inline]
    pub const fn pk_init_len(self) -> usize {
        match self {
            Self::EcdhP384EcdsaP384 => SESSION_P384_SEC1_LEN,
            Self::MlKem1024EcdsaP384 => SESSION_MLKEM1024_PK_LEN,
        }
    }
}

/// Direction of a session transport key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmSessionTransportDir {
    /// VM→HSM (requests).
    H2m,
    /// HSM→VM (responses).
    M2h,
}

/// Session management interface.
///
/// All methods take an [`HsmIo`] handle, which scopes the operation to
/// the calling partition: a session created by partition A is
/// invisible to partition B.  The trait is `&self`; PAL
/// implementations are expected to use interior mutability for the
/// session table (the firmware is single-core, cooperatively
/// scheduled, so a plain `Cell`/`RefCell` suffices).
pub trait HsmSessionManager: HsmIoTypes {
    /// Returns `true` if the calling partition has no free session
    /// slots.
    ///
    /// Used by DDI handlers to short-circuit `OpenSession` requests
    /// with [`HsmError::VaultSessionLimitReached`] before allocating
    /// any crypto state.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    ///
    /// # Returns
    ///
    /// - `true` — every session slot for this partition is in use.
    /// - `false` — at least one slot is free; a subsequent
    ///   [`session_create`](Self::session_create) with `id == None`
    ///   may succeed.
    fn session_limit_reached(&self, io: &Self::Io) -> bool;

    /// Creates a new session, or re-keys an existing one in place.
    ///
    /// The session is committed immediately. (Rollback of a
    /// half-completed handshake will be handled by a future undo log,
    /// not here.)
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `api_rev` — 8-byte API-revision tag stored alongside the
    ///   masking key; later compared by
    ///   [`session_state`](Self::session_state) to detect post-
    ///   migration drift.
    /// - `masking_key` — 80-byte masking-key blob to seal into the
    ///   session vault entry.
    /// - `id` — `None` to allocate a new slot; `Some(existing)` to
    ///   re-key an already-open session in place (post-migration
    ///   renegotiation).  The existing session must currently be in
    ///   [`HsmSessionState::NeedsRenegotiation`]; other states and
    ///   out-of-range IDs are rejected before any vault state is
    ///   touched (see the errors below).
    ///
    /// # Returns
    ///
    /// - `Ok(sess_id)` — the new session's [`HsmSessId`].
    /// - `Err(HsmError::VaultSessionLimitReached)` — `id == None` and
    ///   no slots are free (see
    ///   [`session_limit_reached`](Self::session_limit_reached)), or
    ///   `id == Some(_)` and the ID is out of range.
    /// - `Err(HsmError::SessionNotFound)` — `id == Some(_)` and the
    ///   slot is not allocated.
    /// - `Err(HsmError::ProcessedIoEventInInvalidState)` — `id == Some(_)`
    ///   and the slot is Active or Pending rather than awaiting
    ///   renegotiation.
    /// - `Err(HsmError::InvalidArg)` — `api_rev` or `masking_key` is
    ///   the wrong length. Lengths are checked before the session ID
    ///   or state.
    /// - `Err(HsmError::NotEnoughSpace)` — vault is full and cannot
    ///   store the masking blob.
    async fn session_create(
        &self,
        io: &Self::Io,
        api_rev: &[u8],
        masking_key: &HsmDmaBuf,
        id: Option<HsmSessId>,
    ) -> HsmResult<HsmSessId>;

    /// Closes a session.
    ///
    /// Tears down the session in this order:
    ///
    /// 1. Removes every session-scoped vault key.
    /// 2. Releases PAL-owned session state, including any pending
    ///    handshake state.
    /// 3. Frees the session table slot.
    ///
    /// An unknown or already-free slot returns [`HsmError::SessionNotFound`].
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — session to close.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::SessionNotFound)` — `id` does not refer to an allocated
    ///   session in the caller's partition.
    async fn session_destroy(&self, io: &Self::Io, id: HsmSessId) -> HsmResult<()>;

    /// Rolls back an in-place re-key performed by
    /// [`session_create`](Self::session_create) with `id == Some(_)`
    /// (the post-migration `ReopenSession` path).
    ///
    /// A `ReopenSession` re-keys a
    /// [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation) slot:
    /// it installs a fresh masking-key vault entry and clears the slot's
    /// renegotiation flag, flipping it to [`Active`](HsmSessionState::Active).
    /// If a later step of the same command fails (e.g. the response
    /// cannot be encoded), the host never learns the session was
    /// re-keyed and will retry the reopen — but the now-`Active` slot
    /// would reject that retry.  This call undoes the re-key so the slot
    /// returns to a freshly-migrated `NeedsRenegotiation` state:
    ///
    /// 1. Deletes the fresh masking-key vault entry that
    ///    [`session_create`](Self::session_create) installed.
    /// 2. Restores the slot's renegotiation flag and clears its physical
    ///    vault mapping.
    ///
    /// The slot itself is **not** freed (it still represents a migrated
    /// session awaiting renegotiation), mirroring the reference
    /// firmware's `rollback_open_session` reopen branch
    /// (`session_table().rollback_recreation(id)`).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — session that was just re-keyed and must be restored.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::SessionNotFound)` — `id` does not refer to a
    ///   live slot in the caller's partition.
    async fn session_rollback_reopen(&self, io: &Self::Io, id: HsmSessId) -> HsmResult<()>;

    /// Queries the lifecycle state of a session slot.
    ///
    /// This is an infallible probe: an unknown or freed slot is
    /// reported as [`HsmSessionState::Invalid`] rather than an
    /// `HsmError`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — session slot to probe.
    ///
    /// # Returns
    ///
    /// One of [`HsmSessionState::Active`],
    /// [`HsmSessionState::NeedsRenegotiation`], or
    /// [`HsmSessionState::Invalid`].
    fn session_state(&self, io: &Self::Io, id: HsmSessId) -> HsmSessionState;

    /// Reserves a session slot in the [`Pending`](HsmSessionState::Pending)
    /// state for an in-flight session-establishment handshake.
    ///
    /// Phase 1 of the session protocol: the slot holds the handshake
    /// secret and transcript hash so that the `OpenSessionFinish`
    /// handler can verify the host's confirmation and derive the final
    /// session keys.
    ///
    /// The chosen slot is constrained by `role`:
    ///
    /// - [`HsmSessionRole::CryptoOfficer`] → slot 0 only.
    /// - [`HsmSessionRole::CryptoUser`] → slots 1..=7.
    ///
    /// Allocation policy within the eligible range:
    ///
    /// 1. If an `Empty` slot exists, allocate there.
    /// 2. Otherwise the oldest `Pending` slot in the range is destroyed
    ///    (via [`session_destroy`](Self::session_destroy)) and
    ///    re-allocated.  An evicted handshake's late `OpenSessionFinish`
    ///    fails to authenticate because the slot's transport keys are
    ///    different.
    /// 3. Otherwise (all eligible slots `Active` or
    ///    `NeedsRenegotiation`) returns
    ///    [`HsmError::VaultSessionLimitReached`].
    ///
    /// The `handshake_state` blob is stored opaquely on the slot until
    /// promotion or destruction; the PAL must size internal storage
    /// for blobs up to
    /// [`SESSION_PENDING_BLOB_MAX`](crate::SESSION_PENDING_BLOB_MAX)
    /// bytes.
    ///
    /// The blob's trailing `2 × SESSION_TRANSPORT_KEY_LEN` bytes are the
    /// transport keys `h2m ‖ m2h`;
    /// [`session_transport_key`](Self::session_transport_key) serves the
    /// Pending slot from them, so `OpenSessionFinish` already travels on
    /// the encrypted channel.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `role` — role the handshake is claiming.
    /// - `handshake_state` — opaque handshake material ending with the
    ///   transport keys; retrieved verbatim by
    ///   [`session_pending_state`](Self::session_pending_state).
    ///
    /// # Returns
    ///
    /// - `Ok(id)` — allocated Pending slot.
    /// - `Err(HsmError::InvalidArg)` — IO's bound partition out of range, or
    ///   `handshake_state.len() > SESSION_PENDING_BLOB_MAX`.
    /// - `Err(HsmError::VaultSessionLimitReached)` — no eligible slot
    ///   available for `role`.
    async fn session_create_pending(
        &self,
        io: &Self::Io,
        role: HsmSessionRole,
        handshake_state: &HsmDmaBuf,
    ) -> HsmResult<HsmSessId>;

    /// Borrows the opaque handshake state of a
    /// [`Pending`](HsmSessionState::Pending) slot.
    ///
    /// Used by the `OpenSessionFinish` handler to recover the handshake
    /// secret and transcript hash from the Pending slot before verifying
    /// the client's confirmation MAC.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — Pending session slot.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok(size)` — bytes written / would be written.
    /// - `Err(HsmError::InvalidArg)` — `id` does not refer to a live
    ///   session in the caller's partition, or `out.len() < size`.
    /// - `Err(HsmError::SessionNotPending)` — slot exists but is not
    ///   in [`Pending`](HsmSessionState::Pending) state.
    fn session_pending_state(
        &self,
        io: &Self::Io,
        id: HsmSessId,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Promotes a [`Pending`](HsmSessionState::Pending) slot to
    /// [`Active`](HsmSessionState::Active), committing the derived
    /// session keys to the vault.
    ///
    /// Phase 2 of the session protocol: called by the
    /// `OpenSessionFinish` handler after the client's confirmation MAC
    /// verifies.  The Pending handshake state is zeroized and replaced
    /// by the session-key vault blob:
    ///
    /// 204 B blob = `[api_rev(8) ‖ param_key(32) ‖ masking_key(32) ‖
    /// auth_binding(68) ‖ h2m(32) ‖ m2h(32)]`, identical for CO and CU.
    ///
    /// On error the slot is left untouched; callers may either retry
    /// `session_promote` with corrected arguments or
    /// [`session_destroy`](Self::session_destroy) the slot.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — Pending session slot to promote.
    /// - `api_rev` — 8-byte API revision tag (same convention as
    ///   [`session_create`](Self::session_create)).
    /// - `param_key` — 32-byte AES-256 key used by
    ///   [`tsra_fw_core_crypto_aead_envelope`] for per-parameter
    ///   authenticated encryption (and to unseal the `seed_envelope`
    ///   in `OpenSessionFinish`).
    /// - `masking_key` — 32-byte AES-256-GCM key, required for both CO and
    ///   CU sessions. Consumed by the `key_masking::aead` masked-key system,
    ///   separately from the per-parameter `param_key`.
    /// - `auth_binding` — [`SESSION_AUTH_BINDING_LEN`] bytes captured from
    ///   the authenticated handshake: role, AppId and PSK digest.
    /// - `h2m_key` — [`SESSION_TRANSPORT_KEY_LEN`] VM→HSM transport key.
    /// - `m2h_key` — [`SESSION_TRANSPORT_KEY_LEN`] HSM→VM transport key.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success; slot transitions Pending → Active.
    /// - `Err(HsmError::InvalidArg)` — bad arguments (wrong key
    ///   lengths, `api_rev` wrong length, `id` out of range).
    /// - `Err(HsmError::SessionNotPending)` — slot exists but is not
    ///   in [`Pending`](HsmSessionState::Pending) state.
    #[allow(clippy::too_many_arguments)]
    async fn session_promote(
        &self,
        io: &Self::Io,
        id: HsmSessId,
        api_rev: &[u8],
        param_key: &HsmDmaBuf,
        masking_key: &HsmDmaBuf,
        auth_binding: &HsmDmaBuf,
        h2m_key: &HsmDmaBuf,
        m2h_key: &HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Borrows a session's directional AES-256-GCM transport key.
    ///
    /// Served from a [`Pending`](HsmSessionState::Pending) slot's
    /// handshake blob tail, or from an [`Active`](HsmSessionState::Active)
    /// session's schedule blob.
    ///
    /// # Returns
    ///
    /// - `Ok(&HsmDmaBuf)` — exactly [`SESSION_TRANSPORT_KEY_LEN`] bytes.
    /// - `Err(HsmError::SessionNotFound)` — `id` is neither Pending nor
    ///   Active in the caller's partition.
    /// - `Err(HsmError::InvalidPermissions)` — the session carries no
    ///   transport keys (a legacy MBOR session).
    fn session_transport_key(
        &self,
        io: &Self::Io,
        id: HsmSessId,
        dir: HsmSessionTransportDir,
    ) -> HsmResult<&HsmDmaBuf>;

    /// Returns a borrowed view of the active session's `param_key`
    /// (a 32-byte AES-256 key used by
    /// [`tsra_fw_core_crypto_aead_envelope`]).
    ///
    /// Zero-copy: the returned `&HsmDmaBuf` borrows directly from the
    /// PAL's session-schedule storage, so callers can hand it to
    /// PAL crypto primitives without an intermediate allocation.
    /// This hides the layout of the session schedule blob from
    /// in-session handlers — they no longer need to know that the
    /// schedule is stored as `api_rev ‖ param_key ‖ masking_key …`
    /// behind a vault key.  If the schedule format changes, only
    /// the PAL impl needs to update.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — Active session slot.
    ///
    /// # Returns
    ///
    /// - `Ok(&HsmDmaBuf)` — a sub-view of the schedule blob, exactly
    ///   [`SESSION_PARAM_KEY_LEN`] bytes long.
    /// - `Err(HsmError::SessionNotFound)` — `id` does not refer to a
    ///   live Active session in the caller's partition (slot free,
    ///   destroyed, or still Pending).
    /// - `Err(HsmError::InternalError)` — schedule blob is shorter
    ///   than expected (corruption indicator).
    fn session_param_key(&self, io: &Self::Io, id: HsmSessId) -> HsmResult<&HsmDmaBuf>;

    /// Returns the credential binding captured by the TBOR handshake.
    ///
    /// Legacy MBOR sessions must return `InvalidPermissions`, not a view
    /// into their unrelated masking-key schedule.
    fn session_auth_binding(&self, io: &Self::Io, id: HsmSessId) -> HsmResult<&HsmDmaBuf>;

    /// Returns a borrowed view of the active session's masking key.  Its
    /// length depends on the session's schedule-blob format:
    ///
    /// * a TBOR **SessionEx (CU/CO)** blob yields
    ///   [`SESSION_MASKING_KEY_LEN`] (32 B) of AES-256-GCM key material,
    ///   consumed by the `key_masking::aead` masked-key system;
    /// * a **legacy MBOR `Session`** blob yields a **separate** 80 B
    ///   `aes32 ‖ hmac48` AES-CBC key, consumed by `key_masking::cbc`.
    ///
    /// Callers must therefore take the length from the returned slice
    /// rather than assuming a single fixed size.
    ///
    /// Zero-copy: like [`session_param_key`](Self::session_param_key)
    /// the returned `&HsmDmaBuf` borrows directly from the PAL's
    /// session-schedule storage, so in-session key-creating handlers
    /// can hand it to the masking primitive without an intermediate
    /// allocation to envelope a session-scoped key into a
    /// host-re-importable masked-key blob (persistent keys use the
    /// partition masking key instead).  This hides the schedule blob
    /// layout from handlers.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — Active session slot.
    ///
    /// # Returns
    ///
    /// - `Ok(&HsmDmaBuf)` — a sub-view of the schedule blob whose length
    ///   depends on the blob format: 32 B ([`SESSION_MASKING_KEY_LEN`])
    ///   for a TBOR `SessionEx` session, or 80 B for a legacy MBOR
    ///   `Session` blob.
    /// - `Err(HsmError::SessionNotFound)` — `id` does not refer to a
    ///   live Active session in the caller's partition (slot free,
    ///   destroyed, or still Pending).
    /// - `Err(HsmError::InternalError)` — schedule blob is shorter
    ///   than expected (corruption indicator).
    fn session_masking_key(&self, io: &Self::Io, id: HsmSessId) -> HsmResult<&HsmDmaBuf>;

    /// Atomically reserves the session's one-shot "PSK change"
    /// budget.  Each session may successfully consume this budget at
    /// most once.
    ///
    /// The budget is bound to one logical session for the slot's
    /// lifetime and reset whenever the slot is re-allocated
    /// (`session_destroy`, `session_create`, `session_create_pending`
    /// reuse) or rebound to new key material via re-keying
    /// (`session_recreate`, `session_promote`).
    ///
    /// Used by the TBOR `ChangePsk` handler to bound intra-session
    /// rotation replay.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — Active session slot.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — budget consumed; the call site may proceed.  No
    ///   second `Ok(())` will be returned for this session.
    /// - `Err(HsmError::InvalidPermissions)` — budget already
    ///   consumed by a prior successful call.
    /// - `Err(HsmError::SessionNotFound)` — `id` does not refer to a
    ///   live Active session in the caller's partition (slot free,
    ///   destroyed, or still Pending).
    fn session_try_consume_psk_change(&self, io: &Self::Io, id: HsmSessId) -> HsmResult<()>;
}
