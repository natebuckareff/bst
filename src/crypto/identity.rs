use std::fmt;

use anyhow::{Result, anyhow};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, ed25519::signature::SignerMut};
use rand_core::{OsRng, TryRngCore};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};

pub const IDENTITY_SECRET_KEY_LEN: usize = ed25519_dalek::SECRET_KEY_LENGTH;
pub const IDENTITY_PUBLIC_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const IDENTITY_SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

pub struct IdentitySecretKey {
    key: ed25519_dalek::SigningKey,
}

impl IdentitySecretKey {
    pub fn from_str(string: &str) -> Result<Self> {
        let parsed = base_62::decode(string).map_err(|_| anyhow!("failed to parse secret key"))?;
        let bytes: [u8; IDENTITY_SECRET_KEY_LEN] = parsed
            .try_into()
            .map_err(|_| anyhow!("invalid secret key"))?;
        Ok(Self::from_bytes(bytes))
    }

    pub fn from_bytes(mut secret_key: [u8; SECRET_KEY_LENGTH]) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
        // secret_key.zeroize();
        Self { key }
    }

    pub fn to_string(&self) -> String {
        base_62::encode(&self.key.to_bytes())
    }

    pub fn generate() -> Result<IdentitySecretKey> {
        let mut secret_key = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        OsRng
            .try_fill_bytes(&mut secret_key)
            .map_err(|_| anyhow!("os rng not available"))?;
        Ok(Self::from_bytes(secret_key))
    }

    pub fn get_public_key(&self) -> IdentityPublicKey {
        let key = ed25519_dalek::VerifyingKey::from(&self.key);
        IdentityPublicKey { key }
    }

    pub fn sign(&mut self, msg: &[u8]) -> ed25519_dalek::Signature {
        self.key.sign(msg)
    }
}

#[derive(Clone)]
pub struct IdentityPublicKey {
    key: ed25519_dalek::VerifyingKey,
}

impl IdentityPublicKey {
    pub fn from_str(string: &str) -> Result<Self> {
        let parsed = base_62::decode(string).map_err(|_| anyhow!("failed to parse secret key"))?;
        let bytes: [u8; IDENTITY_PUBLIC_KEY_LEN] = parsed
            .try_into()
            .map_err(|_| anyhow!("invalid public key"))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)?;
        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8; IDENTITY_PUBLIC_KEY_LEN] {
        self.key.as_bytes()
    }

    pub fn as_string(&self) -> String {
        base_62::encode(self.key.as_bytes())
    }

    pub fn verify(&self, msg: &[u8], sig: &IdentitySignature) -> bool {
        match self.key.verify_strict(msg, &sig.sig) {
            Ok(()) => true,
            Err(_) => false,
        }
    }
}

impl Serialize for IdentityPublicKey {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(self.as_string().as_str())
    }
}

impl<'de> Deserialize<'de> for IdentityPublicKey {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeyVisitor;

        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = IdentityPublicKey;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a base-62-encoded Ed25519 public key")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                IdentityPublicKey::from_str(v).map_err(E::custom)
            }
        }

        de.deserialize_str(KeyVisitor)
    }
}

pub struct IdentitySignature {
    sig: ed25519_dalek::Signature,
}

impl IdentitySignature {
    pub fn from_bytes(bytes: &[u8; ed25519_dalek::SIGNATURE_LENGTH]) -> Self {
        let sig = ed25519_dalek::Signature::from_bytes(bytes);
        Self { sig }
    }

    pub fn to_bytes(self) -> [u8; ed25519_dalek::SIGNATURE_LENGTH] {
        self.sig.to_bytes()
    }
}
