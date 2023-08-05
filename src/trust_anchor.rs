use pki_types::{CertificateDer, TrustAnchor};

use crate::cert::{lenient_certificate_serial_number, Cert, EndEntityOrCa};
use crate::der;
use crate::error::{DerTypeId, Error};

/// Interprets the given DER-encoded certificate as a `TrustAnchor`. The
/// certificate is not validated. In particular, there is no check that the
/// certificate is self-signed or even that the certificate has the cA basic
/// constraint.
pub fn extract_trust_anchor<'a>(cert: &'a CertificateDer<'a>) -> Result<TrustAnchor<'a>, Error> {
    let cert_der = untrusted::Input::from(cert.as_ref());

    // XXX: `EndEntityOrCA::EndEntity` is used instead of `EndEntityOrCA::CA`
    // because we don't have a reference to a child cert, which is needed for
    // `EndEntityOrCA::CA`. For this purpose, it doesn't matter.
    //
    // v1 certificates will result in `Error::BadDer` because `parse_cert` will
    // expect a version field that isn't there. In that case, try to parse the
    // certificate using a special parser for v1 certificates. Notably, that
    // parser doesn't allow extensions, so there's no need to worry about
    // embedded name constraints in a v1 certificate.
    match Cert::from_der(cert_der, EndEntityOrCa::EndEntity) {
        Ok(cert) => Ok(TrustAnchor::from(cert)),
        Err(Error::UnsupportedCertVersion) => {
            extract_trust_anchor_from_v1_cert_der(cert_der).or(Err(Error::BadDer))
        }
        Err(err) => Err(err),
    }
}

/// Parses a v1 certificate directly into a TrustAnchor.
fn extract_trust_anchor_from_v1_cert_der(
    cert_der: untrusted::Input<'_>,
) -> Result<TrustAnchor<'_>, Error> {
    // X.509 Certificate: https://tools.ietf.org/html/rfc5280#section-4.1.
    cert_der.read_all(Error::BadDer, |cert_der| {
        der::nested(
            cert_der,
            der::Tag::Sequence,
            Error::TrailingData(DerTypeId::TrustAnchorV1),
            |cert_der| {
                let anchor = der::nested(
                    cert_der,
                    der::Tag::Sequence,
                    Error::TrailingData(DerTypeId::TrustAnchorV1TbsCertificate),
                    |tbs| {
                        // The version number field does not appear in v1 certificates.
                        lenient_certificate_serial_number(tbs)?;

                        skip(tbs, der::Tag::Sequence)?; // signature.
                        skip(tbs, der::Tag::Sequence)?; // issuer.
                        skip(tbs, der::Tag::Sequence)?; // validity.
                        let subject = der::expect_tag(tbs, der::Tag::Sequence)?;
                        let spki = der::expect_tag(tbs, der::Tag::Sequence)?;

                        Ok(TrustAnchor {
                            subject: subject.as_slice_less_safe().into(),
                            subject_public_key_info: spki.as_slice_less_safe().into(),
                            name_constraints: None,
                        })
                    },
                );

                // read and discard signatureAlgorithm + signature
                skip(cert_der, der::Tag::Sequence)?;
                skip(cert_der, der::Tag::BitString)?;

                anchor
            },
        )
    })
}

impl<'a> From<Cert<'a>> for TrustAnchor<'a> {
    fn from(cert: Cert<'a>) -> Self {
        Self {
            subject: cert.subject.as_slice_less_safe().into(),
            subject_public_key_info: cert.spki.as_slice_less_safe().into(),
            name_constraints: cert
                .name_constraints
                .map(|nc| nc.as_slice_less_safe().into()),
        }
    }
}

fn skip(input: &mut untrusted::Reader, tag: der::Tag) -> Result<(), Error> {
    der::expect_tag(input, tag).map(|_| ())
}
