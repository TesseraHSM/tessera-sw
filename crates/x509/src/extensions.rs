// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use der::Decode;
use der::Reader;
use der::Tag;
use der::TagNumber;
use der::asn1::AnyRef;
use der::asn1::BitStringRef;
use der::asn1::ContextSpecific;
use der::asn1::ObjectIdentifier;
use der::asn1::OctetStringRef;

use crate::X509Certificate;
use crate::X509CertificateError;

impl X509Certificate {
    /// Return the certificate's original DER SubjectPublicKeyInfo, without
    /// decoding and re-encoding its public key.
    pub fn subject_public_key_info_der(&self) -> Result<&[u8], X509CertificateError> {
        let parse = || -> der::Result<&[u8]> {
            self.tbs()?.sequence(|tbs| {
                if tbs.peek_tag()?
                    == (Tag::ContextSpecific {
                        constructed: true,
                        number: TagNumber::N0,
                    })
                {
                    AnyRef::decode(tbs)?;
                }
                for _ in 0..5 {
                    AnyRef::decode(tbs)?;
                }
                let spki = tbs.tlv_bytes()?;
                while !tbs.is_finished() {
                    AnyRef::decode(tbs)?;
                }
                Ok(spki)
            })
        };
        parse().map_err(extension_error)
    }

    fn tbs(&self) -> der::Result<AnyRef<'_>> {
        AnyRef::from_der(self.as_der())?.sequence(|certificate| {
            let tbs = AnyRef::decode(certificate)?;
            AnyRef::decode(certificate)?;
            BitStringRef::decode(certificate)?;
            Ok(tbs)
        })
    }

    /// Return an extension's inner DER value, rejecting duplicate extension OIDs.
    pub fn extension_value(&self, oid: &str) -> Result<Option<&[u8]>, X509CertificateError> {
        let parse = || -> der::Result<Option<&[u8]>> {
            let oid = ObjectIdentifier::new(oid)?;
            self.tbs()?.sequence(|tbs| {
                if tbs.peek_tag()?
                    == (Tag::ContextSpecific {
                        constructed: true,
                        number: TagNumber::N0,
                    })
                {
                    AnyRef::decode(tbs)?;
                }
                // Serial, signature, issuer, validity, subject and SPKI.
                for _ in 0..6 {
                    AnyRef::decode(tbs)?;
                }
                for number in [TagNumber::N1, TagNumber::N2] {
                    if !tbs.is_finished()
                        && tbs.peek_tag()?
                            == (Tag::ContextSpecific {
                                constructed: false,
                                number,
                            })
                    {
                        AnyRef::decode(tbs)?;
                    }
                }
                if tbs.is_finished() {
                    return Ok(None);
                }
                let extensions = ContextSpecific::<AnyRef>::decode_explicit(tbs, TagNumber::N3)?
                    .ok_or_else(|| tbs.error(der::ErrorKind::Failed))?;
                extensions.value.sequence(|extensions| {
                    let mut seen = Vec::new();
                    let mut found = None;
                    while !extensions.is_finished() {
                        extensions.sequence(|extension| {
                            let id = ObjectIdentifier::decode(extension)?;
                            if seen.contains(&id) {
                                return Err(extension.error(der::ErrorKind::Failed));
                            }
                            seen.push(id);
                            if extension.peek_tag()? == Tag::Boolean {
                                bool::decode(extension)?;
                            }
                            let value = OctetStringRef::decode(extension)?;
                            if id == oid {
                                found = Some(value.as_bytes());
                            }
                            Ok(())
                        })?;
                    }
                    Ok(found)
                })
            })
        };
        parse().map_err(extension_error)
    }

    /// Whether DICE TCB Info explicitly contains the specified layer.
    /// Missing layer is not equivalent to layer zero.
    pub fn has_dice_tcb_info_layer(&self, expected: u32) -> Result<bool, X509CertificateError> {
        let Some(value) = self.extension_value("2.23.133.5.4.1")? else {
            return Ok(false);
        };
        AnyRef::from_der(value)
            .and_then(|value| {
                value.sequence(|fields| {
                    let mut previous = None;
                    let mut matches = false;
                    while !fields.is_finished() {
                        let Tag::ContextSpecific { number, .. } = fields.peek_tag()? else {
                            return Err(fields.error(der::ErrorKind::Failed));
                        };
                        if previous.is_some_and(|previous| previous >= number) {
                            return Err(fields.error(der::ErrorKind::Failed));
                        }
                        previous = Some(number);
                        if number == TagNumber::N4 {
                            let layer =
                                ContextSpecific::<u32>::decode_implicit(fields, TagNumber::N4)?
                                    .ok_or_else(|| fields.error(der::ErrorKind::Failed))?;
                            matches = layer.value == expected;
                        } else {
                            AnyRef::decode(fields)?;
                        }
                    }
                    Ok(matches)
                })
            })
            .map_err(extension_error)
    }

    /// Whether the EKU extension contains the specified purpose OID.
    pub fn has_extended_key_usage(&self, oid: &str) -> Result<bool, X509CertificateError> {
        let Some(value) = self.extension_value("2.5.29.37")? else {
            return Ok(false);
        };
        let parse = || -> der::Result<bool> {
            let expected = ObjectIdentifier::new(oid)?;
            AnyRef::from_der(value)?.sequence(|purposes| {
                let mut found = false;
                while !purposes.is_finished() {
                    found |= ObjectIdentifier::decode(purposes)? == expected;
                }
                Ok(found)
            })
        };
        parse().map_err(extension_error)
    }
}

fn extension_error(error: der::Error) -> X509CertificateError {
    tracing::error!(?error, "Invalid certificate extension DER");
    X509CertificateError::ExtensionParseError
}
