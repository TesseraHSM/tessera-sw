// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Out-of-band SGL descriptor packing shared by TBOR commands that ship
//! DER certificate chains / reports out of band (`PartFinal`, the SD
//! backup family).
//!
//! Each item ships as its own OOB SGL Data Block; the firmware locates it
//! by the descriptor's `index` (its position in the shared `oob` item
//! list) and reads `length` bytes from it.

use tsra_ddi_tbor_types::*;

use super::*;

pub(crate) trait InputOobItems<'a> {
    fn item_count(&self) -> usize;
    fn push_input(&mut self, input: &'a [u8]);
}

impl<'a> InputOobItems<'a> for Vec<&'a [u8]> {
    fn item_count(&self) -> usize {
        Vec::len(self)
    }

    fn push_input(&mut self, input: &'a [u8]) {
        self.push(input);
    }
}

impl<'a> InputOobItems<'a> for Vec<TborOobItem<'a>> {
    fn item_count(&self) -> usize {
        Vec::len(self)
    }

    fn push_input(&mut self, input: &'a [u8]) {
        self.push(TborOobItem::In(input));
    }
}

/// Appends a certificate chain's DER bytes to `oob`, returning the
/// matching `(index, length)` descriptors. Rejects an empty chain, a
/// chain longer than `max_certs`, an empty (zero-length) cert, or a cert
/// whose length overflows the 16-bit descriptor field.
pub(crate) fn push_cert_chain<'a>(
    chain: &'a [HsmCert<'a>],
    oob: &mut impl InputOobItems<'a>,
    max_certs: usize,
) -> HsmResult<Vec<CertDescriptor>> {
    // Firmware evidence verification rejects an empty chain as InvalidArg;
    // fail fast rather than round-trip a guaranteed rejection.
    if chain.is_empty() || chain.len() > max_certs {
        return Err(HsmError::InvalidArgument);
    }
    let mut descriptors = Vec::with_capacity(chain.len());
    for cert in chain {
        let der = cert.cert;
        if der.is_empty() || der.len() > u16::MAX as usize {
            return Err(HsmError::InvalidArgument);
        }
        // Descriptor index = position in the shared OOB list (must fit u8).
        let index = u8::try_from(oob.item_count()).map_err(|_| HsmError::InvalidArgument)?;
        descriptors.push(CertDescriptor {
            index,
            length: tbor_int::U16::new(der.len() as u16),
        });
        oob.push_input(der);
    }
    Ok(descriptors)
}

/// Appends a COSE_Sign1 report DER to `oob`, returning its descriptor.
/// Rejects an empty report (firmware verification rejects `report_len ==
/// 0` as InvalidArg) or one exceeding the 16-bit length.
pub(crate) fn push_report<'a>(
    report: &'a [u8],
    oob: &mut impl InputOobItems<'a>,
) -> HsmResult<ReportDescriptor> {
    if report.is_empty() || report.len() > u16::MAX as usize {
        return Err(HsmError::InvalidArgument);
    }
    let index = u8::try_from(oob.item_count()).map_err(|_| HsmError::InvalidArgument)?;
    let descriptor = ReportDescriptor {
        index,
        length: tbor_int::U16::new(report.len() as u16),
    };
    oob.push_input(report);
    Ok(descriptor)
}

/// Truncates the out-of-band report buffer to the firmware-reported length.
pub(crate) fn take_report(mut report: Vec<u8>, report_len: tbor_int::U16) -> HsmResult<Vec<u8>> {
    let len = usize::from(report_len.get());
    if len == 0 || len > report.len() {
        return Err(HsmError::InternalError);
    }
    report.truncate(len);
    Ok(report)
}

pub(crate) fn take_sd_backup(report: Vec<u8>, report_len: tbor_int::U16) -> HsmResult<Vec<u8>> {
    let backup = take_report(report, report_len)?;
    if !remote_backup_len_valid(backup.len()) {
        return Err(HsmError::InternalError);
    }
    Ok(backup)
}

/// Pushes the complete signed backup output buffer as out-of-band item
/// [`SD_BACKUP_REPORT_OOB_INDEX`]; it must precede every input item.
pub(crate) fn push_report_out<'a>(
    report: &'a mut [u8],
    oob: &mut Vec<TborOobItem<'a>>,
) -> HsmResult<()> {
    if oob.len() != SD_BACKUP_REPORT_OOB_INDEX {
        return Err(HsmError::InternalError);
    }
    oob.push(TborOobItem::Out(report));
    Ok(())
}
