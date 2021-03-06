#![feature(cursor_remaining)]

use axum::{
    body,
    body::Bytes,
    extract::{Json, RawBody},
    http::Request,
    routing::get,
    Router,
};
use prio::codec::{decode_u16_items, CodecError, Decode};
use serde::Deserialize;
use std::{fmt, io::Cursor};
//use prio::codec::{Decode, U24};

/*
/* ASCII encoded URL. e.g., "https://example.com" */
opaque Url<1..2^16-1>;

Duration uint64; /* Number of seconds elapsed between two instants */

/* An interval of time of length duration, where start is included and (start +
duration) is excluded. */
struct {
  Time start;
  Duration duration;
} Interval;



/* The various roles in the DAP protocol. */
enum {
  collector(0),
  client(1),
  leader(2),
  helper(3),
} Role;

struct {
  HpkeConfigId id;
  HpkeKemId kem_id;
  HpkeKdfId kdf_id;
  HpkeAeadKdfId aead_id;
  HpkePublicKey public_key;
} HpkeConfig;

opaque HpkePublicKey<1..2^16-1>;
uint16 HpkeAeadId; // Defined in [HPKE]
uint16 HpkeKemId;  // Defined in [HPKE]
uint16 HpkeKdfId;  // Defined in [HPKE]

*/

/*
opaque TaskId[32];
*/
struct TaskID([u8; 32]);

impl std::fmt::Debug for TaskID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TaskID: ")?;

        for i in 0..32 {
            write!(f, "{:02x}", self.0[i])?
        }

        Ok(())
    }
}

impl Decode for TaskID {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        // this should probably be available in codec...?
        let mut data: [u8; 32] = [0; 32];
        for i in 0..32 {
            let b = u8::decode(bytes).unwrap();
            data[i] = b;
        }
        Ok(TaskID(data))
    }
}

/*
Time uint64; /* seconds elapsed since start of UNIX epoch */
*/
#[derive(Debug)]
struct Time(u64);

impl Decode for Time {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Time(u64::decode(bytes)?))
    }
}

/*
  struct {
      ExtensionType extension_type;
      opaque extension_data<0..2^16-1>;
  } Extension;
*/
struct Extension {
    extension_type: ExtensionType,
    extension_data: Vec<u8>,
}

impl Decode for Extension {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let extension_type = ExtensionType::from_u16(u16::decode(bytes)?);
        let extension_data: Vec<u8> = decode_u16_items(&(), bytes)?;

        Ok(Extension {
            extension_type,
            extension_data,
        })
    }
}

impl std::fmt::Debug for Extension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let datalen = self.extension_data.len();
        let datashort = format!("{:02x}{:02x}...{:02x}{:02x}", &self.extension_data[0], &self.extension_data[1], &self.extension_data[datalen-2], &self.extension_data[datalen-1]);
        f.debug_struct("Extension")
            .field("extension_type", &self.extension_type)
            .field("extension_data", &datashort)
            .finish()
    }
}

/*
  enum {
      TBD(0),
      (65535)
  } ExtensionType;
*/
#[derive(Debug)]
enum ExtensionType {
    TBD = 0,
    Test1 = 1, // added here
    TBDmaybeMax = 65535,
}

impl ExtensionType {
    fn from_u16(value: u16) -> ExtensionType {
        match value {
            0 => ExtensionType::TBD,
            1 => ExtensionType::Test1,
            _ => panic!("Unknown value: {}", value),
        }
    }
}

/*
/* Identifier for a server's HPKE configuration */
uint8 HpkeConfigId;
*/
#[derive(Debug)]
struct HpkeConfigId(u8);

impl Decode for HpkeConfigId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(HpkeConfigId(u8::decode(bytes)?))
    }
}

/*
/* An HPKE ciphertext. */
struct {
  HpkeConfigId config_id;    // config ID
  opaque enc<1..2^16-1>;     // encapsulated HPKE key
  opaque payload<1..2^16-1>; // ciphertext
} HpkeCiphertext;
 */
struct HpkeCiphertext {
    config_id: HpkeConfigId,
    enc: Vec<u8>,
    payload: Vec<u8>,
}

impl std::fmt::Debug for HpkeCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let enclen = self.enc.len();
        let encshort = format!("{:02x}{:02x}...{:02x}{:02x}", &self.enc[0], &self.enc[1], &self.enc[enclen-2], &self.enc[enclen-1]);
        let payloadlen = self.payload.len();
        let payloadshort = format!("{:02x}{:02x}...{:02x}{:02x}", &self.payload[0], &self.payload[1], &self.payload[payloadlen-2], &self.payload[payloadlen-1]);
        f.debug_struct("HpkeCiphertext")
            .field("config_id", &self.config_id)
            .field("enc", &encshort)
            .field("payload", &payloadshort)
            .finish()
    }
}

impl Decode for HpkeCiphertext {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let config_id = HpkeConfigId::decode(bytes)?;
        let enc: Vec<u8> = decode_u16_items(&(), bytes)?;
        let payload: Vec<u8> = decode_u16_items(&(), bytes)?;

        Ok(HpkeCiphertext {
            config_id,
            enc,
            payload,
        })
    }
}

/*
/* A nonce used to uniquely identify a report in the context of a DAP task. It
includes the timestamp of the current batch and a random 16-byte value. */
struct {
  Time time;
  uint8 rand[16];
} Nonce;
*/
struct Nonce {
    time: Time,
    rand: [u8; 16],
}

fn u8_array_to_hex(bytes: &[u8]) -> String {
    let mut result = String::new();
    let hexdigits = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];
    for b in bytes {
        result.push_str(hexdigits[(b>>4) as usize]);
        result.push_str(hexdigits[(b & 0x0f) as usize]);
    }
    result
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let randstr = "";
        f.debug_struct("Nonce")
            .field("time", &self.time)
            .field("rand", &u8_array_to_hex(&self.rand))
            .finish()
    }
}

impl Decode for Nonce {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let time = Time::decode(bytes)?;

        let mut data: [u8; 16] = [0; 16];
        for i in 0..16 {
            let b = u8::decode(bytes).unwrap();
            data[i] = b;
        }

        Ok(Nonce { time, rand: data })
    }
}

/*
struct {
  TaskID task_id;
  Nonce nonce;
  Extension extensions<0..2^16-1>;
  HpkeCiphertext encrypted_input_shares<1..2^16-1>;
} Report;
*/
#[derive(Debug)]
struct Report {
    task_id: TaskID,
    nonce: Nonce,
    extensions: Vec<Extension>,
    encrypted_input_shares: Vec<HpkeCiphertext>,
}

impl Decode for Report {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskID::decode(bytes)?;
        let nonce = Nonce::decode(bytes)?;
        let extensions: Vec<Extension> = decode_u16_items(&(), bytes)?;
        let encrypted_input_shares: Vec<HpkeCiphertext> = decode_u16_items(&(), bytes)?;

        if !bytes.is_empty() {
            return Err(CodecError::BytesLeftOver(0)); // TODO should return remaining length, don't know how to determine that
        } else {
            Ok(Report {
                task_id,
                nonce,
                extensions,
                encrypted_input_shares,
            })
        }
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/test", get(get_test).post(post_test));

    async fn root() -> &'static str {
        "Hello, World!"
    }

    async fn get_test() -> &'static str {
        "You need to POST something!"
    }

    async fn post_test(body: body::Bytes) {
        //println!("/test endpoint received POST with this body: {:?}", body);
        let decoded: Report = Report::decode(&mut Cursor::new(&body)).unwrap();
        println!("{:?}", decoded);
    }

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
