use blake2::{
    digest::{
        generic_array::{ArrayLength, GenericArray},
        typenum::{Unsigned, U128, U32, U64},
        FixedOutput, Mac, Update,
    },
    Blake2s256, Digest,
};

use crate::cipher_state::CipherState;

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

pub struct SymmState {
    cipher_state: Option<CipherState>,
    chaining_key: GenericArray<u8, U32>,
    output_hash: GenericArray<u8, U32>,
}

impl SymmState {
    fn init(proto_name: &[u8]) -> Self {
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
            chaining_key: GenericArray::from_slice(&init_state).clone(),
            output_hash: *GenericArray::from_slice(&init_state),
        }
    }

    fn mix_key(mut self, input: GenericArray<u8, U32>) -> Self {
        let (new_key, reinit_key) = hkdf2(&self.chaining_key, &input);
        self.cipher_state = match self.cipher_state {
            Some(k) => Some(k.reset_key(reinit_key)),
            None => Some(CipherState::init(reinit_key)),
        };
        self.chaining_key = new_key;
        self
    }
}

fn hkdf2(
    chained: &GenericArray<u8, Blake2SHashLen>,
    input: &GenericArray<u8, Blake2SHashLen>,
) -> (
    GenericArray<u8, Blake2SHashLen>,
    GenericArray<u8, Blake2SHashLen>,
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
        let a = blake2::Blake2sMac256::new(&GenericArray::from_slice(
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
