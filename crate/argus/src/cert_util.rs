use std::{fs::File, io::Cursor, path::Path};
use std::io::prelude::*;

use anyhow::*;
use openssl::{asn1::Asn1Time, pkey::PKeyRef, symm::Cipher, x509::{X509Builder, X509Ref, extension::{BasicConstraints, SubjectKeyIdentifier}}};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{GeneralNameRef, X509Name, X509NameBuilder, X509NameRef, X509};
use rustls::internal::pemfile::{certs, rsa_private_keys};
use rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};

pub struct CAContainer {
    pub cert: X509,
    pub key: PKey<Private>,
    pub pass_phrase: String
}

impl CAContainer {
    pub fn new(cert: X509, key: PKey<Private>, pass_phrase: String) -> CAContainer {
        CAContainer {cert, key, pass_phrase}
    }

    pub fn load_from_file(cert_path: &Path, key_path: &Path, pass_phrase: String) -> Result<CAContainer>{
        Ok(CAContainer {
            cert: load_cert(cert_path)?,
            key: load_key(key_path, pass_phrase.clone())?,
            pass_phrase
        })
    }

    pub fn save_to_file(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        save_cert(cert_path, &self.cert)?;
        save_key(key_path, &self.key, &self.pass_phrase)?;
        Ok(())
    }
}

pub fn generate_cert(privkey: &PKeyRef<Private>, cn: String) -> Result<X509> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "GB")?;
    x509_name.append_entry_by_text("ST", "IKUIKU")?;
    x509_name.append_entry_by_text("L", "Sikoford")?;
    x509_name.append_entry_by_text("O", "HOMODO CA Limited")?;

    if cn.len() == 0 {
        x509_name.append_entry_by_text("CN", &cn)?
    } else {
        x509_name.append_entry_by_text("CN", "HOMODO SEX Certisikocation Ausikority")?
    }

	let x509_name = x509_name.build();

	let x509_serial = {
        let mut serial_number = BigNum::new()?;
        serial_number.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial_number.to_asn1_integer()?
    };

	let x509_not_before = Asn1Time::days_from_now(0)?;
	let x509_not_after = Asn1Time::days_from_now(365 * 45)?;

	let mut x509 = X509Builder::new()?;
	x509.set_version(2)?;
	x509.set_serial_number(&x509_serial)?;
	x509.set_subject_name(&x509_name)?;
	x509.set_issuer_name(&x509_name)?;
	x509.set_pubkey(&privkey)?;
	x509.set_not_before(&x509_not_before)?;
	x509.set_not_after(&x509_not_after)?;
	x509.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
	x509.append_extension(SubjectKeyIdentifier::new().build(&x509.x509v3_context(None, None))?)?;
	x509.sign(&privkey, MessageDigest::sha256())?;
	Ok(x509.build())
}

pub fn save_cert(file: &Path, cert: &X509Ref) -> Result<()> {
	let mut file = File::create(file)?;
	file.write_all(&cert.to_pem()?)?;
	Ok(())
}

pub fn load_cert(path: &Path) -> Result<X509> {
	let bytes = get_binary_from_file(path)?;
	let cert = X509::from_pem(&bytes)?;
	Ok(cert)
}

pub fn generate_keys() -> Result<PKey<Private>> {
    // 4096は強いらしい、知らんけど
	let rsa = Rsa::generate(4096)?;
	let privkey = PKey::from_rsa(rsa)?;
	Ok(privkey)
}

pub fn save_key(file: &Path, key: &PKeyRef<Private>, pass_phrase: &str) -> Result<()> {
	let mut file = File::create(file)?;
    if pass_phrase.len() == 0 {
        file.write_all(&key.rsa().unwrap().private_key_to_pem_passphrase(Cipher::chacha20_poly1305(),pass_phrase.as_bytes())?)?
    } else {
        file.write_all(&key.rsa().unwrap().private_key_to_pem()?)?
    }
	Ok(())
}

pub fn load_key(path: &Path, pass_phrase: String) -> Result<PKey<Private>> {
	let bytes = get_binary_from_file(path)?;
	let key = if pass_phrase.len() != 0 {
        PKey::private_key_from_pem_passphrase(&bytes, pass_phrase.as_bytes())?
    } else {
        PKey::private_key_from_pem(&bytes)?
    };
	Ok(key)
}

pub fn native_identity(
    certificate: &X509,
    key: &PKey<Private>,
    password: &str
) -> Result<Vec<u8>> {
    Ok(Pkcs12::builder()
        .build(password, "", key, certificate)?
        .to_der()?)
}

pub fn spoof_certificate(
    certificate: &X509,
    ca: &CAContainer,
) -> Result<X509> {
    let mut cert_builder = X509::builder()?;

    let name: &X509NameRef = certificate.subject_name();
    let host_name = copy_name(name)?;
    cert_builder.set_subject_name(&host_name)?;
    cert_builder.set_not_before(certificate.not_before())?;
    cert_builder.set_not_after(certificate.not_after())?;
    cert_builder.set_serial_number(certificate.serial_number())?;
    cert_builder.set_version(2)?;

    if let Some(subject_alternative_name) = copy_alt_names(certificate) {
        let subject_alternative_name =
            subject_alternative_name.build(&cert_builder.x509v3_context(Some(&ca.cert), None))?;
        cert_builder.append_extension(subject_alternative_name)?;
    }

    cert_builder.set_issuer_name(ca.cert.issuer_name())?;
    cert_builder.set_pubkey(&ca.key)?;
    cert_builder.sign(&ca.key, MessageDigest::sha256())?;

    Ok(cert_builder.build())
}

fn copy_name(in_name: &X509NameRef) -> Result<X509Name> {
    let mut copy: X509NameBuilder = X509Name::builder()?;
    for entry in in_name.entries() {
        copy.append_entry_by_nid(
            entry.object().nid(),
            entry
                .data()
                .as_utf8()
                .expect("Expected string as entry in name")
                .as_ref(),
        )
        .expect("Failed to add entry by nid");
    }

    Ok(copy.build())
}

fn copy_alt_names(in_cert: &X509) -> Option<SubjectAlternativeName> {
    match in_cert.subject_alt_names() {
        Some(in_alt_names) => {
            let mut subject_alternative_name = SubjectAlternativeName::new();
            for gn in in_alt_names {
                if let Some(email) = gn.email() {
                    subject_alternative_name.email(email);
                } else if let Some(dns) = gn.dnsname() {
                    subject_alternative_name.dns(dns);
                } else if let Some(uri) = gn.uri() {
                    subject_alternative_name.uri(uri);
                } else if let Some(ipaddress) = gn.ipaddress() {
                    subject_alternative_name.ip(&String::from_utf8(ipaddress.to_vec())
                        .expect("ip address on certificate is not formatted as ascii"));
                }
            }
            Some(subject_alternative_name)
        }
        None => None,
    }
}

pub fn cert_cursor(cert: &X509Ref) -> Result<Cursor<Vec<u8>>> {
	let buffer = cert.to_pem()?;
	Ok(Cursor::new(buffer))
}

pub fn key_cursor(key: &PKeyRef<Private>) -> Result<Cursor<Vec<u8>>> {
	let buffer = key.private_key_to_pem_pkcs8()?;
	Ok(Cursor::new(buffer))
}

pub fn convert_to_rustls(
    cert: &X509,
	privkey: &PKey<Private>,
) -> Result<(Vec<Certificate>, Vec<PrivateKey>)> {
    let mut cert_cursor = cert_cursor(&cert)?;
    let cert_tls = match rustls::internal::pemfile::certs(&mut cert_cursor) {
        Ok(cert) => cert, 
        Err(_) => bail!("")
    };

	let mut privkey_cursor = key_cursor(&privkey)?;
    let privkey_tls = match rustls::internal::pemfile::pkcs8_private_keys(&mut privkey_cursor) {
        Ok(key) => key, 
        Err(_) => bail!("")
    };

	Ok((cert_tls, privkey_tls))
}

pub fn get_binary_from_file(path: &Path) -> Result<Vec<u8>> {
    let mut f = File::open(path)
        .with_context(|| format!("could not opening the file: {:?}", path))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)
        .with_context(|| format!("could not reading from the file: {:?}", path))?;
    Ok(buffer)
}
