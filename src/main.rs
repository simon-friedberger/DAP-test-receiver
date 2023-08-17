#![feature(cursor_remaining)]
#![feature(future_join)]

use axum::{
    body,
    extract::Path,
    http::{Request, StatusCode},
    routing::{get, put},
    Extension, Router,
};
use base64::{engine::general_purpose, Engine};
use hpke::{kem::X25519HkdfSha256, Deserializable, Kem};
use prio::{
    codec::{encode_u16_items, encode_u32_items, Decode, Encode, ParameterizedDecode},
    vdaf::{
        prio3::{Prio3Sum, Prio3SumVec},
        Aggregator, Collector, PrepareTransition, Vdaf,
    },
};
use rand::{thread_rng, Rng};
use std::io::Cursor;
use std::{
    collections::HashMap,
    error::Error,
    future::join,
    sync::{Arc, RwLock},
};
use types::ReportID;

mod types;
use crate::types::{DAPHpkeInfo, DAPRole, HpkeConfig, PlaintextInputShare, Report};

mod hpke_helpers;
use hpke_helpers::decrypt;

type State = Arc<RwLock<HashMap<u8, (Vec<u8>, Vec<u8>)>>>;

async fn get_hpke_config(config_id: u8, Extension(state): Extension<State>) -> Vec<u8> {
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

// Can we try and return a 204 here? - No, our client wants a 200.
async fn put_report(
    Path(task_id): Path<String>,
    body: body::Bytes,
    Extension(state): Extension<State>,
) -> &'static str {
    let state_r = state.read().unwrap();

    print!("Received report for task {}", task_id);
    let task_id: Vec<u8> = general_purpose::URL_SAFE_NO_PAD
        .decode(task_id)
        .expect("base64 decoding of task ID failed.");
    assert_eq!(task_id.len(), 32);
    let report = Report::decode(&mut Cursor::new(&body)).unwrap();

    let mut aad = task_id.clone();
    report.metadata.encode(&mut aad);
    encode_u32_items(&mut aad, &(), &report.public_share);

    assert_eq!(report.encrypted_input_shares.len(), 2);

    let mut pt_shares = Vec::new();
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
            pt_shares.push(
                PlaintextInputShare::decode(&mut Cursor::new(&res))
                    .expect("Failed to decode share."),
            );
        } else {
            println!("ERROR: Encryption key not found.");
        }
    }

    let vdaf = Prio3SumVec::new_sum_vec(2, 3, 10).expect("Failed to create vdaf!");
    recover_measurement(
        vdaf,
        &pt_shares,
        &report.public_share,
        &report.metadata.report_id,
    )
    .or_else(|_| {
        let vdaf = Prio3Sum::new_sum(2, 8).expect("Failed to create vdaf!");
        recover_measurement(
            vdaf,
            &pt_shares,
            &report.public_share,
            &report.metadata.report_id,
        )
    })
    .or_else(|_| {
        let vdaf = Prio3Sum::new_sum(2, 6).expect("Failed to create vdaf!");
        recover_measurement(
            vdaf,
            &pt_shares,
            &report.public_share,
            &report.metadata.report_id,
        )
    })
    .or_else(|_| {
        Err("No usable VDAF found.")
    })
    .unwrap();

    ""
}

fn recover_measurement<T: Vdaf<AggregationParam = ()> + Aggregator<16, 16> + Collector>(
    vdaf: T,
    pt_shares: &Vec<PlaintextInputShare>,
    public_share: &Vec<u8>,
    report_id: &ReportID,
) -> Result<(), Box<dyn Error>> {
    let mut input_shares = Vec::new();

    for (agg_id, pt_share) in pt_shares.iter().enumerate() {
        input_shares.push(<T as Vdaf>::InputShare::decode_with_param(
            &(&vdaf, agg_id),
            &mut Cursor::new(&pt_share.payload),
        )?);
    }

    let public_share: <T as Vdaf>::PublicShare =
        <T as Vdaf>::PublicShare::get_decoded_with_param(&vdaf, &public_share)
            .expect("Failed to decode public share!");

    let mut rng = thread_rng();
    let verify_key = rng.gen();

    let mut prep_states = vec![];
    let mut prep_shares = vec![];
    for (agg_id, input_share) in input_shares.iter().enumerate() {
        let (state, share) = vdaf
            .prepare_init(
                &verify_key,
                agg_id,
                &(),
                &report_id.as_ref(),
                &public_share,
                input_share,
            )
            .unwrap();
        prep_states.push(state);
        prep_shares.push(share);
    }

    let prep_msg = vdaf.prepare_preprocess(prep_shares).unwrap();

    let mut out_shares = vec![vec![]; 2];
    for (agg_id, state) in prep_states.into_iter().enumerate() {
        let out_share = match vdaf.prepare_step(state, prep_msg.clone()).unwrap() {
            PrepareTransition::Finish(out_share) => out_share,
            _ => panic!("unexpected transition"),
        };
        out_shares[agg_id].push(out_share);
    }

    let agg_shares = out_shares
        .into_iter()
        .map(|o| vdaf.aggregate(&(), o).unwrap());
    let agg_res = vdaf.unshard(&(), agg_shares, 1).unwrap();
    println!("...value: {:?}", agg_res);

    Ok(())
}

#[tokio::main]
async fn main() {
    let state = State::default();

    let app1 = Router::new()
        .route(
            "/hpke_config",
            get(|ext: Extension<State>| get_hpke_config(30, ext)),
        )
        .route("/tasks/:id/reports", put(put_report))
        .layer(Extension(state.clone()));
    let app2 = Router::new()
        .route(
            "/hpke_config",
            get(|ext: Extension<State>| get_hpke_config(31, ext)),
        )
        .route("/tasks/:id/reports", put(put_report))
        .layer(Extension(state));

    let server1 =
        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap()).serve(app1.into_make_service());
    let server2 =
        axum::Server::bind(&"0.0.0.0:3001".parse().unwrap()).serve(app2.into_make_service());
    let (res1, res2) = join!(server1, server2).await;
    res1.unwrap();
    res2.unwrap();
}
