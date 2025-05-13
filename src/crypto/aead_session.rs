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
    finished: bool,
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
            finished: false,
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

    fn update(&mut self, is_finished: bool) -> Result<bool> {
        if self.counter < COUNTER_ROLLOVER {
            self.counter += 1;
        } else {
            self.rekey()?;
        }
        if is_finished {
            self.finished = true;
        }
        Ok(is_finished)
    }

    fn get_nonce(&self, counter_bytes: &[u8]) -> chacha20poly1305::Nonce {
        let mut nonce = *self.static_iv;
        for (n, c) in nonce[NONCE_LEN - 8..].iter_mut().zip(counter_bytes) {
            *n ^= c;
        }
        chacha20poly1305::Nonce::from(nonce)
    }

    pub fn encrypt(&mut self, frame: &mut BytesMut) -> Result<bool> {
        if self.finished {
            return Err(anyhow!("session finished"));
        }

        let is_finished = frame.len() == 0;
        let counter_bytes = self.counter.to_be_bytes();
        let nonce = self.get_nonce(&counter_bytes);

        frame.reserve(TAG_LEN);

        self.aead_cipher
            .encrypt_in_place(&nonce, &counter_bytes, frame)
            .context("aead encryption failed")?;

        let mut header = BytesMut::with_capacity(counter_bytes.len());
        header.extend_from_slice(&counter_bytes);
        header.unsplit(frame.split());
        *frame = header;

        self.update(is_finished)
    }

    pub fn decrypt(&mut self, frame: &mut BytesMut) -> Result<bool> {
        if self.finished {
            return Err(anyhow!("session finished"));
        }

        let counter_bytes = frame.split_to(8);
        let nonce = self.get_nonce(&counter_bytes);

        self.aead_cipher
            .decrypt_in_place(&nonce, &counter_bytes[..], frame)
            .context("aead decryption failed")?;

        self.update(frame.len() == 0)
    }
}

#[test]
fn test_encryts_and_decrypts() {
    use aead::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let alice_secret = EphemeralSecret::random_from_rng(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let bob_secret = EphemeralSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_secret);

    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
    let mut alice = AeadSession::new(&alice_shared_secret, true).unwrap();

    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);
    let mut bob = AeadSession::new(&bob_shared_secret, true).unwrap();

    // Simulated network packet
    let mut frame = BytesMut::new();

    // Send first frame
    let message = b"Hello Bob!";
    frame.extend_from_slice(b"Hello Bob!");
    assert_eq!(alice.encrypt(&mut frame).unwrap(), false);
    assert_ne!(&message[..], frame);

    // Receive first frame
    assert_eq!(bob.decrypt(&mut frame).unwrap(), false);
    assert_eq!(&frame[..], b"Hello Bob!");

    // Send reply
    let message = b"Hi Alice!";
    frame.clear();
    frame.extend_from_slice(message);
    assert_eq!(bob.encrypt(&mut frame).unwrap(), false);
    assert_ne!(&frame[..], message);

    // Receive reply
    assert_eq!(alice.decrypt(&mut frame).unwrap(), false);
    assert_eq!(&frame[..], b"Hi Alice!");
    dbg!(&frame);

    // Send end-of-session
    frame.clear();
    assert_eq!(alice.encrypt(&mut frame).unwrap(), true);
    assert_eq!(frame.len(), 8 + 0 + TAG_LEN);

    // Receive end-of-session
    assert_eq!(bob.decrypt(&mut frame).unwrap(), true);
    assert_eq!(frame.len(), 0);

    // Try send reply past end
    frame.extend_from_slice(b"late message");
    assert_eq!(bob.encrypt(&mut frame).is_err(), true);
}
