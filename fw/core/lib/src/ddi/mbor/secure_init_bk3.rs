// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MBOR secure BK3 provisioning. The PIN is volatile and separate from
//! application credentials; successful authentication consumes a tunnel key.

use tsra_fw_ddi_mbor_types::secure_init_bk3::DdiSecureInitBk3Req;
use tsra_fw_ddi_mbor_types::set_init_bk3_pin::DdiSetInitBk3PinReq;
use tsra_fw_ddi_mbor_types::set_init_bk3_pin::DdiSetInitBk3PinResp;

use super::establish_credential::consume_tunnel_key;
use super::establish_credential::decrypt_credential;
use super::establish_credential::derive_credential_keys;
use super::establish_credential::derive_credential_prk;
use super::establish_credential::refresh_nonce;
use super::establish_credential::verify_credential_hmac;
use super::*;

fn validate_public_key(key: &DdiPublicKey<'_>) -> HsmResult<()> {
    if key.key_kind != DdiKeyType::Ecc384Public {
        return Err(HsmError::InvalidKeyType);
    }
    if key.raw.len() != HsmEccCurve::P384.pub_key_len() {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

pub(crate) async fn set_init_bk3_pin<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p HsmDmaBuf> {
    let mut body: DdiSetInitBk3PinReq<'_> = decoder.decode_data()?;
    let _lock = pal.partition_lock(io).await?;
    crate::part_state::part_verify_nonce(pal, io, body.encrypted_credential.nonce)?;
    if crate::part_state::prop_present(
        pal.part_prop_get_bytes(io, HsmPartPropId::BK3_PROV_CREDENTIAL),
    )? {
        return Err(HsmError::Bk3PinAlreadySet);
    }
    validate_public_key(&body.pub_key)?;

    let keys = pal.dma_alloc(io, BK_LEN)?;
    derive_credential_keys(
        pal,
        io,
        body.pub_key.raw,
        body.encrypted_credential.nonce,
        keys,
    )
    .await?;
    let (aes_key, hmac_key) = keys.split_at(32);
    let resp = pal.dma_alloc_var(io, |buf| {
        encode_resp(
            &success_hdr(hdr, DdiOp::SetInitBk3Pin),
            &DdiSetInitBk3PinResp {},
            buf,
        )
    })?;
    verify_credential_hmac(pal, io, &body.encrypted_credential, hmac_key).await?;
    refresh_nonce(pal, io)?;
    decrypt_credential(pal, io, &mut body.encrypted_credential, aes_key).await?;
    consume_tunnel_key(pal, io).await?;

    let credential = pal.dma_alloc(io, 32)?;
    credential[..16].copy_from_slice(body.encrypted_credential.encrypted_id);
    credential[16..].copy_from_slice(body.encrypted_credential.encrypted_pin);
    pal.part_prop_set_bytes(io, HsmPartPropId::BK3_PROV_CREDENTIAL, credential)?;
    Ok(resp)
}

pub(crate) async fn secure_init_bk3<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p HsmDmaBuf> {
    let body: DdiSecureInitBk3Req<'_> = decoder.decode_data()?;
    let _lock = pal.partition_lock(io).await?;
    if crate::part_state::part_is_bk3_initialized(pal, io)? {
        return Err(HsmError::Bk3AlreadyInitialized);
    }
    let encrypted = body.encrypted_bk3;
    crate::part_state::part_verify_nonce(pal, io, encrypted.nonce)?;
    let pin_info = pal.dma_alloc(io, 33)?;
    {
        let credential = match pal.part_prop_get_bytes(io, HsmPartPropId::BK3_PROV_CREDENTIAL) {
            Ok(credential) => credential,
            Err(HsmError::PartPropNotFound) => return Err(HsmError::Bk3PinNotSet),
            Err(err) => return Err(err),
        };
        if credential.len() != 32 {
            return Err(HsmError::InternalError);
        }
        pin_info[..16].copy_from_slice(&credential[16..]);
        pin_info[16..32].copy_from_slice(&credential[..16]);
        pin_info[32] = 0x02;
    }
    validate_public_key(&body.pub_key)?;
    let prk = pal.dma_alloc(io, 48)?;
    derive_credential_prk(pal, io, body.pub_key.raw, prk).await?;
    let transport_info = pal.dma_alloc(io, b"BK3_TRANSPORT_ENC".len())?;
    transport_info.copy_from_slice(b"BK3_TRANSPORT_ENC");
    let keys = pal.dma_alloc(io, BK_LEN)?;
    pal.hkdf_expand(io, HsmHashAlgo::Sha384, prk, Some(transport_info), keys)
        .await?;
    let pin_key = pal.dma_alloc(io, 48)?;
    pal.hkdf_expand(io, HsmHashAlgo::Sha384, prk, Some(pin_info), pin_key)
        .await?;

    let message = pal.dma_alloc(io, 96)?;
    message[..16].copy_from_slice(encrypted.iv);
    message[16..64].copy_from_slice(encrypted.encrypted_bk3);
    message[64..].copy_from_slice(encrypted.nonce);
    let (aes_key, hmac_key) = keys.split_at(32);
    if !pal
        .hmac_verify(
            io,
            HsmHashAlgo::Sha384,
            hmac_key,
            message,
            encrypted.tag_transport,
        )
        .await?
    {
        return Err(HsmError::Bk3TransportTagMismatch);
    }
    if !pal
        .hmac_verify(io, HsmHashAlgo::Sha384, pin_key, message, encrypted.tag_pin)
        .await?
    {
        return Err(HsmError::Bk3PinTagMismatch);
    }
    refresh_nonce(pal, io)?;
    pal.aes_cbc_enc_dec_in_place(
        io,
        HsmAesOp::Decrypt,
        aes_key,
        encrypted.encrypted_bk3,
        encrypted.iv,
        None,
    )
    .await?;
    consume_tunnel_key(pal, io).await?;
    pal.part_prop_clear(io, HsmPartPropId::BK3_PROV_CREDENTIAL)?;

    // Like mainline, failures after key/PIN consumption require a new
    // provisioning handshake. Missing BK_BOOT is recreated by the init helper.
    super::init_bk3::mask_bk3(pal, io, encrypted.encrypted_bk3, hdr, true).await
}
