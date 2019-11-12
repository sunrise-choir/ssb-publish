use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use snafu::{ensure, OptionExt, ResultExt, Snafu};
use ssb_legacy_msg::Message;
use ssb_legacy_msg_data::json::{from_slice, to_string, to_vec, DecodeJsonError, EncodeJsonError};
use ssb_legacy_msg_data::value::Value;
use ssb_legacy_msg_data::LegacyF64;
use ssb_multiformats::multihash::{Multihash, Target};
use ssb_multiformats::multikey::{Multikey, Multisig};

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

pub fn publish<T>(
    content: Content<T>,
    previous_msg_bytes: Option<&[u8]>,
    public_key_bytes: &[u8; 32],
    secret_key_bytes: &[u8],
    timestamp: f64,
) -> Result<Vec<u8>>
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
    let empty_signature = Multisig::from_ed25519([0; 64]);
    let previous_message = match previous_msg_bytes {
        Some(message) => Some(from_slice::<SsbPreviousMessage>(message).context(
            InvalidPreviousMessage {
                message: message.to_owned(),
            },
        )?),
        None => None,
    };

    let (new_seq, previous_key, previous_author) = previous_message
        .map(|msg| {
            (
                msg.value.sequence + 1,
                Some(msg.key),
                Some(msg.value.author),
            )
        })
        .unwrap_or((1, None, None));

    // Make sure the author of the previous message matches the public key we're using to publish
    // with.
    if let Some(previous_author) = previous_author {
        ensure!(previous_author == author, PreviousMessageAuthorIsIncorrect)
    }

    let new_message = Message::<T> {
        content,
        author,
        previous: previous_key,
        sequence: new_seq,
        swapped: false,
        signature: empty_signature,
        timestamp: LegacyF64::from_f64(timestamp).unwrap(),
    };

    let encoded_message = ssb_legacy_msg::json::to_legacy_vec(&new_message, false)
        .map_err(|_| snafu::NoneError)
        .context(LegacyJsonEncodeFailed)?;

    let mut message_value: Value = from_slice(&encoded_message).unwrap();
    // Modify the val by removing the signature
    if let Value::Object(ref mut msg) = message_value {
        msg.remove("signature".to_owned());
    };

    let signable_bytes = to_string(&message_value, false).unwrap();
    let signature_bytes = keypair.sign::<Sha512>(signable_bytes.as_bytes()).to_bytes();
    let signature = Multisig::from_ed25519(signature_bytes);
    let signature_value = Value::String(signature.to_legacy_string());

    // Put the signature back on. Yes, yes, gross.
    if let Value::Object(ref mut msg) = message_value {
        msg.insert("signature".to_owned(), signature_value);
    };

    let value_string = to_string(&message_value, false).unwrap();

    let hashable_bytes = node_buffer_binary_serializer(&value_string);
    let hash = Sha256::digest(&hashable_bytes);
    let key = Multihash::from_sha256(hash.into(), Target::Message);

    let ssb_message = SsbMessage {
        key,
        value: message_value,
    };

    to_vec(&ssb_message, false)
        .map_err(|_| snafu::NoneError)
        .context(LegacyJsonEncodeFailed)
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
    use ssb_validate;
    use ssb_verify_signatures;

    use ed25519_dalek::Keypair;
    use ed25519_dalek::Signature;
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
        let msg1 = publish(
            content,
            None,
            keypair.public.as_bytes(),
            keypair.secret.as_bytes(),
            0.0,
        )
        .unwrap();

        let is_valid1 = ssb_validate::validate_hash_chain(&msg1, None).is_ok();
        let is_verified1 = ssb_verify_signatures::verify(&msg1).is_ok();

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
            keypair.public.as_bytes(),
            keypair.secret.as_bytes(),
            0.0,
        )
        .unwrap();

        let is_valid2 = ssb_validate::validate_hash_chain(&msg2, Some(&msg1)).is_ok();
        let is_verified2 = ssb_verify_signatures::verify(&msg2).is_ok();

        assert!(is_valid1);
        assert!(is_verified1);
        assert!(is_valid2);
        assert!(is_verified2);
    }
}
