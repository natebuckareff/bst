use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use chacha20poly1305::{ChaCha20Poly1305, aead::AeadMutInPlace, aead::KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const SECRET_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const COUNTER_ROLLOVER: u64 = 1 << 62;

type SecretKey<const N: usize> = Zeroizing<[u8; N]>;

pub struct AeadSession {
    phase_key: SecretKey<SECRET_KEY_LEN>,
    static_iv: SecretKey<NONCE_LEN>,
    aead_cipher: ChaCha20Poly1305,
    is_receiver: bool,
    counter: u64,
}

impl AeadSession {
    pub fn new(shared_secret: &x25519_dalek::SharedSecret, is_receiver: bool) -> Result<Self> {
        let initial_key = shared_secret.as_bytes();
        let phase_key = Self::generate_phase_key(initial_key, is_receiver, false)?;
        let static_iv = Self::generate_static_iv(&phase_key, is_receiver)?;
        let aead_cipher = Self::generate_aead_cipher(&phase_key, is_receiver)?;
        Ok(Self {
            phase_key,
            static_iv,
            aead_cipher,
            is_receiver,
            counter: 0,
        })
    }

    fn rekey(&mut self) -> Result<()> {
        let is_receiver = self.is_receiver;
        self.phase_key = Self::generate_phase_key(&self.phase_key, is_receiver, true)?;
        self.static_iv = Self::generate_static_iv(&self.phase_key, is_receiver)?;
        self.aead_cipher = Self::generate_aead_cipher(&self.phase_key, is_receiver)?;
        self.counter = 0;
        Ok(())
    }

    fn generate_phase_key(
        initial_key: &[u8; SECRET_KEY_LEN],
        is_receiver: bool,
        is_rekey: bool,
    ) -> Result<SecretKey<SECRET_KEY_LEN>> {
        let label = Self::get_phase_label(is_receiver, is_rekey);
        let mut key = Zeroizing::new([0u8; SECRET_KEY_LEN]);
        Self::expand_key(initial_key, label, &mut key)?;
        Ok(key)
    }

    fn generate_static_iv(
        initial_key: &[u8; SECRET_KEY_LEN],
        is_receiver: bool,
    ) -> Result<SecretKey<NONCE_LEN>> {
        let label = Self::get_iv_label(is_receiver);
        let mut key = Zeroizing::new([0u8; NONCE_LEN]);
        Self::expand_key(initial_key, label, &mut key)?;
        Ok(key)
    }

    fn generate_aead_cipher(
        initial_key: &[u8; SECRET_KEY_LEN],
        is_receiver: bool,
    ) -> Result<ChaCha20Poly1305> {
        let label = Self::get_aead_label(is_receiver);
        let mut key = Zeroizing::new([0u8; SECRET_KEY_LEN]);
        Self::expand_key(initial_key, label, &mut key)?;
        let cipher_key = chacha20poly1305::Key::from_slice(&*key);
        Ok(ChaCha20Poly1305::new(cipher_key))
    }

    fn get_phase_label(is_receiver: bool, is_rekey: bool) -> &'static str {
        if is_rekey {
            if is_receiver {
                "bst phase rekey recv"
            } else {
                "bst phase rekey send"
            }
        } else {
            if is_receiver {
                "bst phase recv"
            } else {
                "bst phase send"
            }
        }
    }

    fn get_aead_label(is_receiver: bool) -> &'static str {
        if is_receiver {
            "bst aead recv"
        } else {
            "bst aead send"
        }
    }

    fn get_iv_label(is_receiver: bool) -> &'static str {
        if is_receiver {
            "bst iv recv"
        } else {
            "bst iv send"
        }
    }

    fn expand_key<const I: usize, const O: usize>(
        ikm: &[u8; I],
        label: &'static str,
        out: &mut [u8; O],
    ) -> Result<()> {
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let info = label.as_bytes();
        hk.expand(info, out)
            .map_err(|_| anyhow!("failed to derive key material because of invalid length"))?;
        Ok(())
    }

    fn update(&mut self) -> Result<()> {
        if self.counter < COUNTER_ROLLOVER {
            self.counter += 1;
            Ok(())
        } else {
            self.rekey()
        }
    }

    pub fn encrypt(&mut self, frame: &mut BytesMut) -> Result<()> {
        let counter_bytes = self.counter.to_be_bytes();
        let mut nonce = *self.static_iv;
        for (n, c) in nonce[NONCE_LEN - 8..].iter_mut().zip(counter_bytes) {
            *n ^= c;
        }
        let nonce = chacha20poly1305::Nonce::from(nonce);

        frame.reserve(TAG_LEN);

        self.aead_cipher
            .encrypt_in_place(&nonce, &counter_bytes, frame)
            .context("aead encryption failed")?;

        let mut header = BytesMut::with_capacity(counter_bytes.len());
        header.extend_from_slice(&counter_bytes);
        header.unsplit(frame.split());
        *frame = header;

        self.update()
    }

    pub fn decrypt(&mut self, frame: &mut BytesMut) -> Result<()> {
        let counter_bytes = frame.split_to(8);
        let mut nonce = *self.static_iv;
        for (n, c) in nonce[NONCE_LEN - 8..].iter_mut().zip(&counter_bytes) {
            *n ^= c;
        }
        let nonce = chacha20poly1305::Nonce::from(nonce);

        self.aead_cipher
            .decrypt_in_place(&nonce, &counter_bytes[..], frame)
            .context("aead decryption failed")?;

        self.update()
    }
}

#[test]
fn test_encryts_and_decrypts() {
    use aead::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let alice_secret = EphemeralSecret::random_from_rng(OsRng);
    let bob_secret = EphemeralSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_secret);
    let shared_secret = alice_secret.diffie_hellman(&bob_public);

    let mut session = AeadSession::new(&shared_secret, true).unwrap();

    let message = b"Hello, world!";
    let mut frame = BytesMut::new();
    frame.extend_from_slice(message);
    session.encrypt(&mut frame).unwrap();
    let mut frame = frame;
    assert_ne!(&message[..], frame, "is encrypted");

    session.decrypt(&mut frame).unwrap();
    assert_eq!(&message[..], frame, "is decrypted");
}
