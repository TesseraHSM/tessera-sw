// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `RsaModExp` command handler.
//!
//! Within an open session, perform a raw RSA exponentiation using a
//! caller-held **masked** RSA private key (imported via
//! [`UnwrapKey`](super::unwrap_key) with the RSA / RSA-CRT key class). The
//! key is unmasked **in place** in the request buffer and its modulus size /
//! CRT form recovered from the blob's key kind. Public operations derive
//! the public key from that authenticated private key on-device.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use tsra_fw_core_crypto_key_masking::aead::peek_frame;
use tsra_fw_core_crypto_key_masking::aead::unmask_framed;
use tsra_fw_ddi_tbor_types::RsaOp;
use tsra_fw_ddi_tbor_types::TborRsaModExpReq;
use tsra_fw_ddi_tbor_types::TborRsaModExpResp;
use tsra_fw_hsm_pal_traits::HsmByteOrder;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::from_pal::rsa_key;
use super::resolve_masking_key;
use super::validate_active_session;

/// Handle a TBOR `RsaModExp` request.
///
/// No partition lock or undo log is required: the command reads no mutable
/// partition state and **persists nothing** — it unmasks the caller's key,
/// computes the selected raw RSA primitive, and replaces the input integer
/// with its result.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let base = cmd_buf.request().as_ptr() as usize;
    let output_len = pal
        .alloc_scoped_async(io, async |alloc| -> HsmResult<usize> {
            let req = TborRsaModExpReq::decode_mut(cmd_buf.request_mut())?;
            let sess_id = HsmSessId::from(u16::from(req.session_id));
            validate_active_session(pal, io, sess_id)?;
            let public = match RsaOp(req.op_type) {
                RsaOp::Decrypt | RsaOp::Sign => false,
                RsaOp::Encrypt | RsaOp::Verify => true,
                _ => return Err(HsmError::InvalidArg),
            };
            let (scope, frame) = peek_frame(req.masked_key)?;
            let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
            let view = unmask_framed(pal, io, masking_key, req.masked_key, frame).await?;
            let key_type = rsa_key(view.key_kind)?;
            let permitted = match RsaOp(req.op_type) {
                RsaOp::Decrypt => view.key_attrs.decrypt(),
                RsaOp::Sign => view.key_attrs.sign(),
                RsaOp::Encrypt => view.key_attrs.encrypt(),
                RsaOp::Verify => view.key_attrs.verify(),
                _ => return Err(HsmError::InvalidArg),
            };
            if !permitted {
                return Err(HsmError::InvalidPermissions);
            }

            if req.y.len() != key_type.modulus_len() {
                return Err(HsmError::InvalidArg);
            }
            let data_start = tsra_fw_ddi_tbor::REQ_HEADER_LEN + TborRsaModExpReq::TOC_COUNT * 4;
            if (req.y.as_ptr() as usize).checked_sub(base) != Some(data_start) {
                return Err(HsmError::TborNonCanonicalLayout);
            }
            if !public {
                pal.mod_exp_priv_in_place(io, key_type, view.target_key, req.y)
                    .await?;
                return Ok(req.y.len());
            }

            let k = key_type.modulus_len();
            let public_key_len = k + 4;
            if pal.rsa_priv_pub_key(io, view.target_key, None)? != public_key_len {
                return Err(HsmError::InternalError);
            }
            let public_key = alloc.dma_alloc(public_key_len)?;
            if pal.rsa_priv_pub_key(io, view.target_key, Some(public_key))? != public_key_len {
                return Err(HsmError::InternalError);
            }
            if !public_operand_in_range(P::BYTE_ORDER, &public_key[..k], req.y) {
                return Err(HsmError::InvalidArg);
            }

            let result = alloc.dma_alloc(k)?;
            let written = pal
                .mod_exp_pub(
                    io,
                    key_type.pub_variant(),
                    public_key,
                    req.y,
                    Some(&mut *result),
                )
                .await?;
            if written != k {
                return Err(HsmError::InternalError);
            }
            req.y.copy_from_slice(&result[..k]);
            Ok(k)
        })
        .await?;

    cmd_buf.encode_response(|buf| {
        let frame = TborRsaModExpResp::encode_for_request(buf, 0, false)?
            .x_existing(output_len)?
            .finish();
        Ok(frame.as_bytes().len())
    })
}

fn public_operand_in_range(order: HsmByteOrder, modulus: &[u8], operand: &[u8]) -> bool {
    if modulus.len() != operand.len() {
        return false;
    }
    let ordering = if order.is_be() {
        operand.cmp(modulus)
    } else {
        operand.iter().rev().cmp(modulus.iter().rev())
    };
    ordering.is_lt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_operand_bounds_follow_device_order() {
        let modulus_be = [0x01, 0x00, 0xFF];
        for value in [
            [0x00, 0x00, 0x00],
            [0x00, 0x00, 0x01],
            [0x00, 0x00, 0x02],
            [0x01, 0x00, 0xFD],
            [0x01, 0x00, 0xFE],
        ] {
            let expected = value < modulus_be;
            assert_eq!(
                public_operand_in_range(HsmByteOrder::Be, &modulus_be, &value),
                expected
            );
            let modulus_le = [0xFF, 0x00, 0x01];
            let value_le = [value[2], value[1], value[0]];
            assert_eq!(
                public_operand_in_range(HsmByteOrder::Le, &modulus_le, &value_le),
                expected
            );
        }
        assert!(!public_operand_in_range(
            HsmByteOrder::Be,
            &modulus_be,
            &[0x01, 0x00, 0xFF]
        ));
        assert!(!public_operand_in_range(
            HsmByteOrder::Be,
            &modulus_be,
            &[0x01, 0x01, 0x00]
        ));
    }
}
