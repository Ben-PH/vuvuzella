use blake2::{
    digest::{
        generic_array::GenericArray as B2GenericArray,
        typenum::{Unsigned, U128, U32, U64},
        FixedOutput, Mac, Update,
    },
    Blake2s256, Digest,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::cipher_state::{CipherError, CipherPair, CipherState, CipherText, PlainText};

pub type Sh256HashLen = U32;
pub type Sh256BlockLen = U64;

pub type Sh512HashLen = U64;
pub type Sh512BlockLen = U128;

pub type Blake2SHashLen = U32;
pub type Blake2SBlockLen = U64;

pub type Blake2BHashLen = U64;
pub type Blake2BBlockLen = U128;

/// using x25519-dalek
const DH_LEN: usize = 32;

#[derive(Eq, PartialEq)]
pub struct SymmState {
    cipher_state: Option<CipherState>,
    chaining_key: B2GenericArray<u8, U32>,
    output_hash: B2GenericArray<u8, U32>,
}

impl SymmState {
    pub(crate) fn init(proto_name: &[u8]) -> Self {
        let init_state = if proto_name.len() > Blake2SHashLen::USIZE {
            let mut hasher = Blake2s256::new();
            blake2::Digest::update(&mut hasher, proto_name);
            hasher.finalize().into()
        } else {
            let mut init_state = [0; Blake2SHashLen::USIZE];
            init_state[0..proto_name.len()].copy_from_slice(proto_name);
            init_state
        };

        Self {
            cipher_state: None,
            chaining_key: *B2GenericArray::from_slice(&init_state),
            output_hash: *B2GenericArray::from_slice(&init_state),
        }
    }

    pub(crate) fn mix_key(&mut self, input: &B2GenericArray<u8, U32>) {
        let (new_key, reinit_key) = hkdf2(&self.chaining_key, input);

        self.cipher_state = Some(CipherState::init(reinit_key));
        self.chaining_key = new_key;
    }
    fn get_mix_hash(&self, data: &CipherText) -> B2GenericArray<u8, U32> {
        let hasher = Blake2s256::new();
        hasher
            .chain_update(self.output_hash)
            .chain_update(&data.text)
            .chain_update(data.tag)
            .finalize_fixed()
    }
    pub(crate) fn mix_hash(&mut self, data: &[u8]) {
        let hasher = Blake2s256::new();
        self.output_hash = hasher
            .chain_update(self.output_hash)
            .chain_update(data)
            .finalize_fixed();
    }

    /// Generates a secret, and mixes the public key into the output hash. Primarily used for
    /// setting up the writing of an ephemeral public key token
    pub fn gen_key_and_mix(&mut self) -> EphemeralSecret {
        let secret = EphemeralSecret::random();
        let shared_public = PublicKey::from(&secret);
        self.mix_hash(shared_public.as_bytes());
        secret
    }

    fn encrypt_and_hash(mut self, text: PlainText) -> (Self, CipherText) {
        let Some(state) = self.cipher_state else {
            panic!("Invariant broken: attempt to encrypt without a cipherstate present")
        };

        let (new_state, ct) = state.encrypt_with_ad(self.output_hash, text);
        self.cipher_state = new_state;
        self.output_hash = self.get_mix_hash(&ct);
        (self, ct)
    }

    fn decrypt_and_hash(
        self,
        ad: &[u8],
        text: CipherText,
    ) -> Result<(Self, PlainText), (Self, CipherError)> {
        if self.cipher_state.is_none() {
            panic!("Invariant broken: attempt to decrypt without a cipherstate present")
        };
        let next_hash = self.get_mix_hash(&text);
        let Self {
            cipher_state,
            chaining_key,
            ..
        } = self;

        let Ok((new_state, pt)) = cipher_state.unwrap().decrypt_with_ad(ad, text) else {
            todo!("handle decrypion error");
        };

        Ok((
            Self {
                cipher_state: new_state,
                output_hash: next_hash,
                chaining_key,
            },
            pt,
        ))
    }
    /// Used at completion of the handshake. Deletes the symmetric state, and provides a reader/writer [`CipherPair`] 
    pub(crate) fn consume(self) -> CipherPair {
        CipherPair::new(self.cipher_state.unwrap())
    }
}

/// HMAC Key Derivation Function. Provides two outputs.
fn hkdf2(
    chained: &B2GenericArray<u8, Blake2SHashLen>,
    input: &B2GenericArray<u8, Blake2SHashLen>,
) -> (
    B2GenericArray<u8, Blake2SHashLen>,
    B2GenericArray<u8, Blake2SHashLen>,
) {
    let tmp = blake2::Blake2sMac256::new(chained)
        .chain(input)
        .finalize_fixed();
    let out1_hmac = blake2::Blake2sMac256::new(&tmp).chain([1]).finalize_fixed();
    let out2_hmac = blake2::Blake2sMac256::new(&tmp)
        .chain(out1_hmac)
        .chain([2])
        .finalize_fixed();
    (out1_hmac, out2_hmac)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn chain_instead_of_concat() {
        let a = blake2::Blake2sMac256::new(B2GenericArray::from_slice(
            b"fizzbuzz000000000000000000000000",
        ));
        let b = a.clone();

        let left = a.chain(b"foo").chain(b"bar").finalize_fixed();
        let right = b.chain(b"foobar").finalize_fixed();

        eprintln!("{:?}", left.as_slice());
        eprintln!("{:?}", right.as_slice());
        assert_eq!(left, right);
    }
}
