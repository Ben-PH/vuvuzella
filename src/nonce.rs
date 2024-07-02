//! There are special rules about libp2p nonce:
//! Repeated use can be "catastrophic" to use libp2p the specification vocabulary.
//! The max value is reserved.
//!
//! We use rusts type system to encapsulate these rules.

use zeroize::Zeroize;

// TODO: with copy/clone, it is easy to lose track. Ideally, this type wrapper would somehow be
// integrated into the encryption and decryption calls such that the required invariants are upheld
// by lifetime semantics. E.g. a succesful encrypt/decrypt can only occur because an iretreivable,
// singleton nonce move occured, but in its place you obtain the result of the increment call.
#[derive(Zeroize)]
#[cfg_attr(test, derive(Debug))]
pub struct Nonce(u64);

impl Nonce {
    pub fn new() -> Self {
        Self(0)
    }

    /// Consumes the inner nonce, returning the next nonce to be used
    /// When the nonce is exhausted, returns none
    /// #Panics: panics if the reserved max-value for u64 is used
    pub fn chacha_harvest(self) -> ([u8; 12], Option<Self>) {
        if self.0 == u64::MAX {
            panic!("Invariant broken: use of u64::MAX for nonce");
        }
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&self.0.to_le_bytes());
        let next = if self.0 == u64::MAX - 1 {
            None
        } else {
            Some(Self(self.0.saturating_add(1)))
        };

        (nonce, next)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic_inc() {
        let nonce = Nonce::new();
        let (n, next) = nonce.chacha_harvest();
        assert_eq!([0; 12], n);
        assert_eq!(1, next.as_ref().unwrap().0);

        let (n, next) = next.unwrap().chacha_harvest();
        let ref_arr = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(ref_arr, n);
        assert_eq!(2, next.as_ref().unwrap().0);

        let (n, next) = next.unwrap().chacha_harvest();
        let ref_arr = [0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(ref_arr, n);
        assert_eq!(3, next.unwrap().0);
    }
    #[test]
    fn final_inc() {
        let nonce = Nonce(u64::MAX - 1);
        let (last, reserved) = nonce.chacha_harvest();
        let ref_arr = [0, 0, 0, 0, 254, 255, 255, 255, 255, 255, 255, 255];
        assert!(reserved.is_none());
        assert_eq!(ref_arr, last);
    }
    #[test]
    fn le_constructon() {
        let ref_array = [44, 46, 42, 89, 12, 19, 13, 121];
        let ref_num = u64::from_le_bytes(ref_array.clone());
        let ref_nonce = Nonce(ref_num);
        let (n, next) = ref_nonce.chacha_harvest();
        assert_eq!(n[4..], ref_array);
        assert_eq!(ref_num + 1, next.unwrap().0);
    }
    #[test]
    #[should_panic]
    fn max_inc() {
        let nonce = Nonce(u64::MAX);
        let _next = nonce.chacha_harvest();
        eprintln!("should have paniced when trying to harvest an invalid nonce");
    }
}
