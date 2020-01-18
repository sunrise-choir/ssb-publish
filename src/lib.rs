//! Publish signed Secure Scuttlebutt (Ssb) Messages as Json
//!

use std::convert::TryInto;
//use ed25519_dalek::{Keypair, PublicKey, SecretKey, ExpandedSecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::{ensure, ResultExt, Snafu};
use ssb_legacy_msg::Message;
use ssb_legacy_msg_data::json::{from_slice, to_vec, DecodeJsonError};
use ssb_legacy_msg_data::value::{Value, RidiculousStringMap};
use ssb_legacy_msg_data::LegacyF64;
use ssb_multiformats::multihash::{Target};
use ssb_multiformats::multikey::{Multisig, Multikey};
use ssb_crypto::{SecretKey, PublicKey, sign_detached};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Previous message was invalid. Decoding failed with: {}", source))]
    InvalidPreviousMessage {
        source: DecodeJsonError,
        message: Vec<u8>,
    },
    #[snafu(display("Invalid public key"))]
    InvalidPublicKey {},
    #[snafu(display("Invalid secret key"))]
    InvalidSecretKey {},
    #[snafu(display("Previous message author is not the same as the author public_key."))]
    PreviousMessageAuthorIsIncorrect {},
    #[snafu(display("Legacy Json encoding failed with error"))]
    LegacyJsonEncodeFailed {},
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub use ssb_legacy_msg::Content;
pub use ssb_multiformats::multihash::Multihash;

/// Publish a new message.
///
/// - Bring your own ed25519 keys (as bytes)
/// - You choose whether or not to publish actual timestamps or just random numbers.
///
/// Returns a tuple of: 
/// - the new message as a Vec of bytes. This is the message value with keys `previous`, `sequence`,
/// `content` etc.
/// - the [Multihash] (ssb message key) of the new message 
///
/// You may use this to publish public _or_ private messages. 
/// If you want to publish private messages, you'll have to encrypt them first and wrap them in
/// the `Content::Encrypted` enum variant.  
/// 
/// ## Example
///
///```
///  use ssb_publish::{publish, Content};
///  use ssb_multiformats::multikey::Multikey;
///  use ssb_validate::validate_message_hash_chain;
///  use ssb_verify_signatures::verify_message;
///  use serde::{Deserialize, Serialize};
///  use ssb_crypto::{generate_longterm_keypair};
///
///  let (pk, sk) = generate_longterm_keypair();
///
///  #[derive(Serialize, Deserialize, Debug)]
///  #[serde(tag = "type")]
///  #[serde(rename = "contact")]
///  struct Contact {
///      contact: Multikey,
///      following: bool,
///      blocking: bool,
///  }
///  // Create a new `Contact` message.
///  let contact = Contact {
///      contact: Multikey::from_legacy(
///          b"@9Zf0se86PotjNqaOt9ue8BNBLkGVLQcLNDw/pRQHY3U=.ed25519",
///      )
///      .unwrap()
///      .0,
///      following: true,
///      blocking: false,
///  };
///  let content = Content::Plain(contact);
///
///  let msg = publish::<_, &[u8]>(
///      content,
///      None,
///      &pk,
///      &sk,
///      0.0,
///  )
///  .unwrap();
///
///  let is_valid = validate_message_hash_chain::<_, &[u8]>(&msg, None).is_ok();
///  let is_verified = verify_message(&msg).is_ok();
///
///  assert!(is_valid);
///  assert!(is_verified);
///  ```


pub fn publish<T, P>(
    content: Content<T>,
    previous_msg_value_bytes: Option<P>,
    public_key: &PublicKey,
    secret_key: &SecretKey,
    timestamp: f64,
) -> Result<Vec<u8>>
where
    T: Serialize,
    P: AsRef<[u8]>
{

    let author = Multikey::from_ed25519(public_key.as_ref().try_into().unwrap());

    let previous_message = match previous_msg_value_bytes {
        Some(message) => {
            let message = message.as_ref();
            let decoded_previous =
                from_slice::<SsbPreviousMessage>(message).context(InvalidPreviousMessage {
                    message: message.to_owned(),
                })?;
            Some(decoded_previous)
        }
        None => None,
    };

    let (new_seq, previous_key, previous_author) = previous_message
        .map(|msg| (msg.value.sequence + 1, Some(msg.key), Some(msg.value.author)))
        .unwrap_or((1, None, None));

    // Make sure the author of the previous message matches the public key we're using to publish
    // with.
    if let Some(previous_author) = previous_author {
        ensure!(previous_author == author, PreviousMessageAuthorIsIncorrect)
    }

    let mut new_message = Message::<T> {
        content,
        author,
        previous: previous_key,
        sequence: new_seq,
        swapped: false,
        timestamp: LegacyF64::from_f64(timestamp).unwrap(),
        signature: None, // We'll generate the signature below.
    };

    let signable_bytes = ssb_legacy_msg::json::to_legacy_vec(&new_message, false)
        .map_err(|_| snafu::NoneError)
        .context(LegacyJsonEncodeFailed)?;

    let mut sig = [0; 64];

    let signature_bytes = sign_detached(&signable_bytes, secret_key);

    signature_bytes
        .as_ref()
        .iter()
        .enumerate()
        .for_each(|(i, byte)| sig[i] = *byte);

    let signature = Multisig::from_ed25519(&sig);

    new_message.signature = Some(signature);

    let published_bytes = ssb_legacy_msg::json::to_legacy_vec(&new_message, false).unwrap();

    let key = get_multihash_from_message_bytes(&published_bytes);
    let value = from_slice(&published_bytes).unwrap();  

    let mut map = RidiculousStringMap::with_capacity(1);
    map.insert("key".to_owned(), Value::String(key.to_legacy_string()));
    map.insert("value".to_owned(), value);
    let message: Value = Value::Object(map);

    let message_bytes = to_vec(&message, false).unwrap();

    Ok(message_bytes)
}

fn get_multihash_from_message_bytes(bytes: &[u8]) -> Multihash {
    let hashable_bytes = node_buffer_binary_serializer(&std::str::from_utf8(bytes).unwrap());
    let hash = Sha256::digest(&hashable_bytes);
    Multihash::from_sha256(hash.into(), Target::Message)
}
fn node_buffer_binary_serializer(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .map(|word| (word & 0xFF) as u8)
        .collect()
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SsbPreviousMessageValue {
    previous: Option<Multihash>,
    author: Multikey,
    sequence: u64,
    timestamp: LegacyF64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SsbPreviousMessage {
    key: Multihash,
    value: SsbPreviousMessageValue,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SsbMessage {
    key: Multihash,
    value: Value,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename = "contact")]
struct Contact {
    contact: Multikey,
    following: bool,
    blocking: bool,
}

#[cfg(test)]
mod tests {
    use crate::{publish, Contact, Content};
    use ssb_multiformats::multikey::Multikey;
    use ssb_validate::validate_message_hash_chain;
    use ssb_verify_signatures::verify_message;
    use ssb_crypto::{generate_longterm_keypair};


    #[test]
    fn it_works() {
        let (pk, sk) =  generate_longterm_keypair();

        let contact = Contact {
            contact: Multikey::from_legacy(
                b"@9Zf0se86PotjNqaOt9ue8BNBLkGVLQcLNDw/pRQHY3U=.ed25519",
            )
            .unwrap()
            .0,
            following: true,
            blocking: false,
        };
        let content = Content::Plain(contact);
        let msg1 = publish::<_, &[u8]>(
            content,
            None,
            &pk,
            &sk,
            0.0,
        )
        .unwrap();

        let is_valid1 = validate_message_hash_chain::<_, &[u8]>(&msg1, None).is_ok();
        let is_verified1 = verify_message(&msg1).is_ok();

        let contact = Contact {
            contact: Multikey::from_legacy(
                b"@9Zf0se86PotjNqaOt9ue8BNBLkGVLQcLNDw/pRQHY3U=.ed25519",
            )
            .unwrap()
            .0,
            following: false,
            blocking: false,
        };
        let content = Content::Plain(contact);
        let msg2 = publish(
            content,
            Some(&msg1),
            &pk,
            &sk,
            0.0,
        )
        .unwrap();

        let is_valid2 = validate_message_hash_chain(&msg2, Some(&msg1)).is_ok();
        let is_verified2 = verify_message(&msg2).is_ok();

        assert!(is_valid1);
        assert!(is_verified1);
        assert!(is_valid2);
        assert!(is_verified2);
    }
}
