//! just using chacha20poly1305 and blake2s for now.
use blake2::digest::{typenum::U32, generic_array::GenericArray};
use chacha20poly1305::{consts::U16, AeadInPlace, KeyInit};
use zeroize::Zeroize;

use crate::{nonce::Nonce, symm_state::Blake2SHashLen};

#[derive(Zeroize)]
struct PlainText(Vec<u8>);
struct CipherText {
    text: Vec<u8>,
    tag: chacha20poly1305::aead::generic_array::GenericArray<u8, U16>,
}

const KEY_LEN: usize = 32;
struct CipherKey(GenericArray<u8, Blake2SHashLen>);

impl CipherKey {
    fn valid_key(&self) -> bool {
        self.0.iter().any(|&b| b != 0)
    }
}

pub struct CipherState {
    nonce: Nonce,
    key: CipherKey,
}

enum CipherError {
    Opaque,
    Decrypt,
}

impl CipherState {
    pub(crate) fn init(new_key: GenericArray<u8, Blake2SHashLen>) -> Self {
        let key = CipherKey(new_key);
        assert!(
            key.valid_key(),
            "invariant breakage: attempt to initialise empty key"
        );
        Self {
            nonce: Nonce::new(),
            key,
        }
    }
    /// Refreshes the cipher state with a new key, setting nonce to 0.
    pub(crate) fn reset_key(self, new_key: GenericArray<u8, Blake2SHashLen>) -> Self {
        let key = CipherKey(new_key);
        assert!(
            key.valid_key(),
            "invariant breakage: attempt to reset key to empty key"
        );
        Self {
            nonce: Nonce::new(),
            key,
        }
    }

    fn encrypt_with_ad(
        self,
        assosciated_data: &[u8],
        plain_text: PlainText,
    ) -> (Option<Self>, CipherText) {
        assert!(
            self.key.valid_key(),
            "invariant broken: attempt to encrypt wth empty key"
        );

        // trade nonce for next-nonce + cipher-text
        let (text, next_nonce) = encrypt(&self.key, self.nonce, assosciated_data, plain_text)
            .expect("todo: handle encryption error");

        // lift the nonce to cipherstate
        let me_res = next_nonce.map(|n| Self {
            nonce: n,
            key: self.key,
        });
        // return result
        (me_res, text)
    }

    fn decrypt_with_ad(
        self,
        assosciated_data: &[u8],
        cipher_text: CipherText,
    ) -> Result<(Option<Self>, PlainText), (Self, CipherText, CipherError)> {
        assert!(
            !self.key.0.iter().any(|&b| b != 0),
            "invariant broken: attempt to decrypt wth empty key"
        );
        let Ok((text, me_res)) = decrypt(&self.key, self.nonce, assosciated_data, cipher_text)
        else {
            panic!("todo: recover the previous nonce, and return error");
        };

        Ok((
            me_res.map(|n| Self {
                nonce: n,
                key: self.key,
            }),
            text,
        ))
    }
}

/// Trades a nonce and plain-text for ciphertext + next nonce
fn encrypt(
    key: &CipherKey,
    nonce: Nonce,
    ad: &[u8],
    mut text: PlainText,
) -> Result<(CipherText, Option<Nonce>), ()> {
    assert!(
        !key.0.iter().any(|&b| b != 0),
        "invariant broken: attempt to encrypt wth empty key"
    );
    let (nonce_arr, fresh_nonce) = nonce.chacha_harvest();
    let aead = chacha20poly1305::ChaCha20Poly1305::new(&key.0.into());

    let tag = aead.encrypt_in_place_detached(&nonce_arr.into(), ad, &mut text.0);

    let ct = CipherText {
        text: text.0,
        tag: tag.unwrap(),
    };
    Ok((ct, fresh_nonce))
}

// attempt to trade nonce + ciphertext for plaintext
fn decrypt(
    key: &CipherKey,
    nonce: Nonce,
    ad: &[u8],
    mut text: CipherText,
) -> Result<(PlainText, Option<Nonce>), (CipherText, Nonce, CipherError)> {
    assert!(
        !key.0.iter().any(|&b| b != 0),
        "invariant broken: attempt to decrypt wth empty key"
    );

    let aead = chacha20poly1305::ChaCha20Poly1305::new(&key.0.into());
    let (n_arr, next_nonce) = nonce.chacha_harvest();
    match aead.decrypt_in_place(&n_arr.into(), ad, &mut text.text) {
        Ok(()) => Ok((PlainText(text.text), next_nonce)),
        Err(_) => todo!("auth error: recover previous nonce and return it and ciphertext"),
    }
}
