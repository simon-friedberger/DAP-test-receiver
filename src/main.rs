#![feature(cursor_remaining)]
#![feature(future_join)]

use axum::{
    body,
    body::Bytes,
    extract::{Json, Path, RawBody},
    http::{Request, StatusCode},
    routing::{get, post, put},
    Extension, Router,
};
use base64::{engine::general_purpose, Engine};
use hpke::{kem::X25519HkdfSha256, Deserializable, Kem};
use prio::{codec::{
    decode_u16_items, encode_u16_items, encode_u32_items, CodecError, Decode, Encode, ParameterizedDecode,
}, vdaf::{prio3::{Prio3SumVec, Prio3InputShare}, Collector, Aggregator}};
use serde::Deserialize;
use std::{
    collections::HashMap,
    future::join,
    sync::{Arc, RwLock},
};
use std::{fmt, io::Cursor};
//use prio::codec::{Decode, U24};

mod types;
use crate::types::{DAPHpkeInfo, DAPRole, HpkeConfig, PlaintextInputShare, Report, TaskID};

mod hpke_helpers;
use hpke_helpers::decrypt;

type State = Arc<RwLock<HashMap<u8, (Vec<u8>, Vec<u8>)>>>;

#[tokio::main]
async fn main() {
    let state = State::default();

    let app1 = Router::new()
        .route("/", get(root))
        .route(
            "/hpke_config",
            get(|ext: Extension<State>| get_hpke_config(30, ext)),
        )
        .route("/tasks/:id/reports", put(put_report))
        .layer(Extension(state.clone()));
    let app2 = Router::new()
        .route("/", get(root))
        .route(
            "/hpke_config",
            get(|ext: Extension<State>| get_hpke_config(31, ext)),
        )
        .route("/tasks/:id/reports", put(put_report))
        .layer(Extension(state));

    async fn root() -> &'static str {
        println!("[ root handler ]");
        "Hello, World! :)"
    }

    async fn get_hpke_config(config_id: u8, Extension(state): Extension<State>) -> Vec<u8> {
        println!("[ get_hpke_config2 handler ]");
        let mut state_w = state.write().unwrap();
        let keypair = state_w
            .entry(config_id)
            .or_insert_with(hpke_helpers::generate_keypair);
        let pubkeybytes = keypair.1.clone();
        let mut bytes: Vec<u8> = Vec::new();
        encode_u16_items(
            &mut bytes,
            &(),
            &vec![HpkeConfig::new_testing(config_id, pubkeybytes)],
        );
        bytes
    }

    // Can we try and return a 204 here? - Maybe, but our client wants a 200.
    async fn put_report(
        Path(task_id): Path<String>,
        body: body::Bytes,
        Extension(state): Extension<State>,
    ) -> &'static str {
        println!("[ put_report handler ]");
        let state_r = state.read().unwrap();

        let task_id: Vec<u8> = general_purpose::URL_SAFE_NO_PAD
            .decode(task_id)
            .expect("base64 decoding of task ID failed.");
        assert_eq!(task_id.len(), 32);
        let report = Report::decode(&mut Cursor::new(&body)).unwrap();
        println!("Received report: Metadata: {:?}", report.metadata);

        let mut aad = task_id.clone();
        report.metadata.encode(&mut aad);
        encode_u32_items(&mut aad, &(), &report.public_share);

        assert_eq!(report.encrypted_input_shares.len(), 2);

        for i in 0..2 {
            let enc_share = &report.encrypted_input_shares[i];
            if let Some(keypair) = state_r.get(&enc_share.config_id.into()) {
                let res = decrypt(
                    &<X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&keypair.0).unwrap(),
                    <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&enc_share.enc).unwrap(),
                    &enc_share.payload,
                    &aad,
                    &(if i == 0 {
                        DAPHpkeInfo::new(DAPRole::Client, DAPRole::Leader)
                    } else {
                        DAPHpkeInfo::new(DAPRole::Client, DAPRole::Helper)
                    }),
                );
                let ptis = PlaintextInputShare::decode(&mut Cursor::new(&res))
                    .expect("Failed to decode share.");
            } else {
                println!("ERROR: Encryption key not found.");
            }
        }

        // TODO: It would be nice to decrypt both payloads and recombine the
        // shares.
        ""
    }

    let server1 =
        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap()).serve(app1.into_make_service());
    let server2 =
        axum::Server::bind(&"0.0.0.0:3001".parse().unwrap()).serve(app2.into_make_service());
    let (res1, res2) = join!(server1, server2).await;
    res1.unwrap();
    res2.unwrap();
}
