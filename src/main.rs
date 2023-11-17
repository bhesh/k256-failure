use der::{DecodePem, Encode};
use ecdsa::{Signature, VerifyingKey};
use sha2::Sha256;
use signature::{digest::Digest, hazmat::PrehashVerifier, Verifier};
use std::fs;
use x509_cert::{request::CertReq, Certificate};

fn main() {
    let pem = fs::read_to_string("testdata/secp256k1-sha256-crt.pem").unwrap();
    let cert = Certificate::from_pem(&pem).unwrap();
    let pem = fs::read_to_string("testdata/secp256k1-sha256-req.pem").unwrap();
    let req = CertReq::from_pem(&pem).unwrap();

    let key: VerifyingKey<k256::Secp256k1> = VerifyingKey::from_sec1_bytes(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .unwrap();

    let msg = cert.tbs_certificate.to_der().unwrap();
    let sig = Signature::<k256::Secp256k1>::from_der(&cert.signature.raw_bytes()).unwrap();

    print!("Verifying self-signed certificate using verify() ... ");
    match key.verify(&msg, &sig) {
        Ok(_) => println!("verification successful"),
        Err(e) => println!("failed: {}", e),
    }
    print!("Verifying self-signed certificate using verify_prehash() ... ");
    match key.verify_prehash(&Sha256::digest(&msg), &sig) {
        Ok(_) => println!("verification successful"),
        Err(e) => println!("failed: {}", e),
    }

    let msg = req.info.to_der().unwrap();
    let sig = Signature::<k256::Secp256k1>::from_der(&req.signature.raw_bytes()).unwrap();

    print!("Verifying certificate request using verify() ... ");
    match key.verify(&msg, &sig) {
        Ok(_) => println!("verification successful"),
        Err(e) => println!("failed: {}", e),
    }
    print!("Verifying certificate request using verify_prehash() ... ");
    match key.verify_prehash(&Sha256::digest(&msg), &sig) {
        Ok(_) => println!("verification successful"),
        Err(e) => println!("failed: {}", e),
    }
}
