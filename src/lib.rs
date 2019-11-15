//! Publish signed Secure Scuttlebutt (Ssb) Messages as Json
//!

use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use snafu::{ensure, ResultExt, Snafu};
use ssb_legacy_msg::Message;
use ssb_legacy_msg_data::json::{from_slice, DecodeJsonError};
use ssb_legacy_msg_data::value::Value;
use ssb_legacy_msg_data::LegacyF64;
use ssb_multiformats::multihash::{Target};
use ssb_multiformats::multikey::{Multisig, Multikey};

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
///  # use ed25519_dalek::Keypair;
///  # use rand::OsRng;
///  # use rand::Rng;
///  # use sha2::Sha512;
///  use ssb_publish::{publish, Content};
///  use ssb_multiformats::multikey::Multikey;
///  use ssb_validate::validate_message_value_hash_chain;
///  use ssb_verify_signatures::verify_message_value;
///  use serde::{Deserialize, Serialize};
///  # let mut csprng: OsRng = OsRng::new().unwrap();
///  # let keypair: Keypair = Keypair::generate::<Sha512, _>(&mut csprng);
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
///  // This example is using ed25519_dalek for crypto, but you can use whatever you want.
///  let (msg, _) = publish(
///      content,
///      None,
///      keypair.public.as_bytes(),
///      keypair.secret.as_bytes(),
///      0.0,
///  )
///  .unwrap();
///
///  let is_valid = validate_message_value_hash_chain::<_, &[u8]>(&msg, None).is_ok();
///  let is_verified = verify_message_value(&msg).is_ok();
///
///  assert!(is_valid);
///  assert!(is_verified);
///  ```


pub fn publish<T>(
    content: Content<T>,
    previous_msg_value_bytes: Option<&[u8]>,
    public_key_bytes: &[u8; 32],
    secret_key_bytes: &[u8],
    timestamp: f64,
) -> Result<(Vec<u8>, Multihash)>
where
    T: Serialize,
{
    let public_key: PublicKey = PublicKey::from_bytes(&public_key_bytes[..])
        .map_err(|_| snafu::NoneError)
        .context(InvalidPublicKey)?;
    let secret_key: SecretKey = SecretKey::from_bytes(&secret_key_bytes[..])
        .map_err(|_| snafu::NoneError)
        .context(InvalidSecretKey)?;
    let keypair: Keypair = Keypair {
        secret: secret_key,
        public: public_key,
    };
    let author = Multikey::from_ed25519(*public_key_bytes);

    let previous_message = match previous_msg_value_bytes {
        Some(message) => {
            let decoded_previous =
                from_slice::<SsbPreviousMessageValue>(message).context(InvalidPreviousMessage {
                    message: message.to_owned(),
                })?;
            let previous_key = get_multihash_from_message_bytes(message);
            Some((decoded_previous, previous_key))
        }
        None => None,
    };

    let (new_seq, previous_key, previous_author) = previous_message
        .map(|(msg, key)| (msg.sequence + 1, Some(key), Some(msg.author)))
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

    let signature_bytes = keypair.sign::<Sha512>(&signable_bytes).to_bytes();
    let signature = Multisig::from_ed25519(signature_bytes);

    new_message.signature = Some(signature);

    let published_bytes = ssb_legacy_msg::json::to_legacy_vec(&new_message, false).unwrap();

    let key = get_multihash_from_message_bytes(&published_bytes);

    Ok((published_bytes, key))
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
    use ssb_validate::validate_message_value_hash_chain;
    use ssb_verify_signatures::verify_message_value;

    use ed25519_dalek::Keypair;
    use rand::OsRng;
    use rand::Rng;
    use sha2::Sha512;

    #[test]
    fn it_works() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate::<Sha512, _>(&mut csprng);

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
        let (msg1, _) = publish(
            content,
            None,
            keypair.public.as_bytes(),
            keypair.secret.as_bytes(),
            0.0,
        )
        .unwrap();

        let is_valid1 = validate_message_value_hash_chain::<_, &[u8]>(&msg1, None).is_ok();
        let is_verified1 = verify_message_value(&msg1).is_ok();

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
        let (msg2, _) = publish(
            content,
            Some(&msg1),
            keypair.public.as_bytes(),
            keypair.secret.as_bytes(),
            0.0,
        )
        .unwrap();

        let is_valid2 = validate_message_value_hash_chain(&msg2, Some(&msg1)).is_ok();
        let is_verified2 = verify_message_value(&msg2).is_ok();

        assert!(is_valid1);
        assert!(is_verified1);
        assert!(is_valid2);
        assert!(is_verified2);
    }
}
