use der::{DecodePem, Encode};
use ecdsa::{Signature, VerifyingKey};
use hex_literal::hex;
use sha2::Sha256;
use signature::{digest::Digest, hazmat::PrehashVerifier};
use std::fs;
use x509_cert::{request::CertReq, Certificate};

fn by_hex() {
    let key: VerifyingKey<k256::Secp256k1> = VerifyingKey::from_sec1_bytes(
        &hex!(
            "04bc72f5435bc947f3b79132dab7946159b28be519068960cfb10300c7124776d
             98ab5cb70229f99e149c3c695c301d604bad15e84ee1ed0abbb8c5b8e9782fdb0"
        )[..],
    )
    .unwrap();

    // Works
    let prehash = hex!("7e0bb97c6efdcb06156b17a56d41741c4b282b1f6840baec169cca08ec461c60");
    let sig = Signature::<k256::Secp256k1>::from_scalars(
        hex!("D7597474A3CE9FC900A846DBC40D80D9EF3716C60C008113931990FBAB34E301"),
        hex!("5657331ECCA94B78BD83DE48B53F4A99F9067D90EF9A742E5752E32D1E94EDC7"),
    )
    .unwrap();
    print!("Testing signature 1 ... ");
    match key.verify_prehash(&prehash[..], &sig) {
        Ok(_) => println!("verification successful"),
        Err(e) => println!("failed: {}", e),
    }

    // Fails
    let prehash = hex!("a9ac0a346a96a91fa6aefb92b65ae6ad0f73ad1d3a113ab4454e4c0e5b25469a");
    let sig = Signature::<k256::Secp256k1>::from_scalars(
        hex!("DDBD927A63D95426A1A17E2096EA7B5B3227F12694FE0092B7227A83EFF0487E"),
        hex!("F84A1D9BEC6F304CDB8564F7CE4A2665235FCAE2B1F524F5F4004E793A854808"),
    )
    .unwrap();
    print!("Testing signature 2 ... ");
    match key.verify_prehash(&prehash[..], &sig) {
        Ok(_) => println!("verification successful"),
        Err(e) => println!("failed: {}", e),
    }
}

fn by_file() {
    let pem = fs::read("testdata/secp256k1-sha256-crt.pem").unwrap();
    let cert = Certificate::from_pem(pem).unwrap();
    let pem = fs::read("testdata/secp256k1-sha256-req.pem").unwrap();
    let req = CertReq::from_pem(pem).unwrap();

    let key: VerifyingKey<k256::Secp256k1> = VerifyingKey::from_sec1_bytes(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .unwrap();

    let prehash = Sha256::digest(req.info.to_der().unwrap());
    let sig = Signature::<k256::Secp256k1>::from_der(req.signature.raw_bytes()).unwrap();
    print!("Testing signature 1 ... ");
    match key.verify_prehash(&prehash[..], &sig) {
        Ok(_) => println!("verification successful"),
        Err(e) => println!("failed: {}", e),
    }

    let prehash = Sha256::digest(cert.tbs_certificate.to_der().unwrap());
    let sig = Signature::<k256::Secp256k1>::from_der(cert.signature.raw_bytes()).unwrap();
    print!("Testing signature 2 ... ");
    match key.verify_prehash(&prehash[..], &sig) {
        Ok(_) => println!("verification successful"),
        Err(e) => println!("failed: {}", e),
    }
}

fn main() {
    println!("Testing with x509 objects");
    by_file();
    println!("\nTest with raw scalars");
    by_hex();
}
