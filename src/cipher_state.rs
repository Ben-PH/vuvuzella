//! just using chacha20poly1305 and blake2s for now.
use chacha20poly1305::{aead::generic_array::GenericArray as CCGenericArr,  consts::{U16, U32}, AeadInPlace, KeyInit};
use zeroize::Zeroize;

use crate::{nonce::Nonce, symm_state::Blake2SHashLen};

#[derive(Zeroize)]
pub(crate) struct PlainText(Vec<u8>);

pub(crate) struct CipherText {
    pub(crate) text: Vec<u8>,
    pub(crate) tag: CCGenericArr<u8, U16>,
}

const KEY_LEN: usize = 32;
struct CipherKey(CCGenericArr<u8, Blake2SHashLen>);


impl CipherKey {
    fn valid_key(&self) -> bool {
        self.0.iter().any(|&b| b != 0)
    }
}

pub struct CipherState {
    nonce: Nonce,
    key: CipherKey,
}

pub enum CipherError {
    Opaque,
    Decrypt,
}

impl CipherState {
    pub(crate) fn init(new_key: CCGenericArr<u8, Blake2SHashLen>) -> Self {
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
    pub(crate) fn reset_key(self, new_key: CCGenericArr<u8, Blake2SHashLen>) -> Self {
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

    /// trades current cipher-state + aead encryption detals for the next cipher state + ciphertext
    /// By "next state": Samke cipher key, with the nonce incremented.
    pub(crate) fn encrypt_with_ad(
        self,
        assosciated_data: CCGenericArr<u8, U32>,
        plain_text: PlainText,
    ) -> (Option<Self>, CipherText) {
        assert!(
            self.key.valid_key(),
            "invariant broken: attempt to encrypt wth empty key"
        );

        // trade nonce for next-nonce + cipher-text
        let (next_me, text) = self.do_encrypt(plain_text, assosciated_data);// encrypt(&self.key, self.nonce, assosciated_data, plain_text)

        // return result
        (next_me, text)
    }

    pub(crate) fn decrypt_with_ad(
        self,
        assosciated_data: &[u8],
        cipher_text: CipherText,
    ) -> Result<(Option<Self>, PlainText), (Self, CipherText, CipherError)> {
        assert!(
            !self.key.0.iter().any(|&b| b != 0),
            "invariant broken: attempt to decrypt wth empty key"
        );
        let Ok(res) = self.do_decrypt(assosciated_data, cipher_text) else {
            panic!("todo: recover the previous nonce, and return error");
        };

        Ok(res)
    }

    /// Trades a nonce/key pair and plain-text +ad pair for ciphertext + next nonce
    pub(crate) fn do_encrypt(self, mut text: PlainText, ad: CCGenericArr<u8, U32>) -> (Option<Self>, CipherText) {
        assert!(
            self.key.valid_key(),
            "invariant broken: attempt to encrypt wth empty key"
        );
        let (nonce_arr, fresh_nonce) = self.nonce.chacha_harvest();
        let aead = chacha20poly1305::ChaCha20Poly1305::new(&self.key.0.into());

        let tag = aead.encrypt_in_place_detached(&nonce_arr.into(), ad.as_slice(), &mut text.0);

        let ct = CipherText {
            text: text.0,
            tag: tag.unwrap(),
        };

        let Some(fresh_nonce) = fresh_nonce else {
            return (None, ct);
        };
        let fresh = Self {
            key: self.key,
            nonce: fresh_nonce,
        };
        (Some(fresh), ct)
    }

    /// Attempt to trade key + nonce pair to decrypt an ad + ct pair for plain-text and next-key +
    /// nonce par
    pub(crate) fn do_decrypt(self, ad: &[u8], mut text: CipherText) -> Result<(Option<Self>, PlainText), (CipherText, Nonce, CipherError)> {
        assert!(
            self.key.valid_key(),
            "invariant broken: attempt to decrypt wth empty key"
        );

        let aead = chacha20poly1305::ChaCha20Poly1305::new(&self.key.0.into());
        let (n_arr, next_nonce) = self.nonce.chacha_harvest();
        let decrypt =  aead.decrypt_in_place_detached(&n_arr.into(), ad, &mut text.text, &text.tag);

        let Ok(()) = decrypt else {
            todo!("auth error: recover previous nonce and return it and ciphertext");
        };

        let res = next_nonce.map(|nn| Self{ nonce: nn, key: self.key });
        Ok((res, PlainText(text.text)))
    }
}
