use hpke::{aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, Kem, OpModeR, Serializable};
use rand::SeedableRng;

use crate::types::DAPHpkeInfo;

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let (privkey, pubkey) = X25519HkdfSha256::gen_keypair(&mut rng);
    let privkeybytes = privkey.to_bytes();
    let pubkeybytes = pubkey.to_bytes();

    (privkeybytes.to_vec(), pubkeybytes.to_vec())
}

pub fn decrypt(
    privkey: &<X25519HkdfSha256 as Kem>::PrivateKey,
    encapped_key: <X25519HkdfSha256 as Kem>::EncappedKey,
    ciphertext: &Vec<u8>,
    aad: &[u8],
    info: &DAPHpkeInfo,
) -> Vec<u8> {
    let plaintext = hpke::single_shot_open::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        privkey,
        &encapped_key,
        info.bytes(),
        ciphertext,
        aad,
    )
    .expect("Decryption failed");

    plaintext
}
