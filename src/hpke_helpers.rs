use base64::{engine::general_purpose, Engine};
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305, AesGcm128},
    generic_array::{typenum, GenericArray},
    kdf::{HkdfSha384, HkdfSha256},
    kem::X25519HkdfSha256,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use rand::{Rng, SeedableRng};

use crate::types::{HpkeConfig, DAPHpkeInfo, DAPRole};

fn print_key(key_by: &GenericArray<u8, typenum::U32>, name: &str) {
    println!("Key ({}):", name);
    println!("  hex: {:x}", key_by);
    let key_b64 = general_purpose::URL_SAFE_NO_PAD.encode(key_by);
    println!("  b64: {:?}", key_b64);
}

// TODOtmp
// fn roundtrip_test(
//     privkey: &<X25519HkdfSha256 as Kem>::PrivateKey,
//     pubkey: &<X25519HkdfSha256 as Kem>::PublicKey,
// ) {
//     print!("Roundtrip test ");
//     let mut msg = [0u8; 300];
//     rand::thread_rng().fill(&mut msg[..]);
//     let mut aad = [0u8; 100];
//     rand::thread_rng().fill(&mut aad[..]);
//     let (encapped_key, ciphertext, tag) = encrypt(pubkey, &msg, &aad);
//     let decrypted = decrypt(privkey, encapped_key, ciphertext, &aad);
//     assert_eq!(decrypted, msg);
//     println!("…succeeded.");
// }

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let (privkey, pubkey) = X25519HkdfSha256::gen_keypair(&mut rng);
    let privkeybytes = privkey.to_bytes();
    let pubkeybytes = pubkey.to_bytes();
    // print_key(&privkeybytes, "Private");
    // print_key(&pubkeybytes, "Public");

    // roundtrip_test(&privkey, &pubkey);

    (privkeybytes.to_vec(), pubkeybytes.to_vec())
}

pub fn decrypt(
    privkey: &<X25519HkdfSha256 as Kem>::PrivateKey,
    encapped_key: <X25519HkdfSha256 as Kem>::EncappedKey,
    ciphertext: &Vec<u8>,
    aad: &[u8],
    info: &DAPHpkeInfo,
) -> Vec<u8> {
    let plaintext = hpke::single_shot_open::<AesGcm128, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, privkey, &encapped_key, info.bytes(), ciphertext, aad).expect("Decryption failed");

    plaintext
}
