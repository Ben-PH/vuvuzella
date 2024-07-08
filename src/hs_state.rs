use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::symm_state::SymmState;

#[derive(Zeroize)]
struct KeyPair(chacha20poly1305::Key);
struct HsState {
    e: EphemeralSecret,
    re: PublicKey,
    pattern: Pattern,
    role: Role,
}

enum Pattern {
    // NN,
    XX,
    // NK,
    // KK,
}

enum Role {
    Initiator,
    Responder,
}

impl HsState {
    pub fn init(
        pattern: Pattern,
        role: Role,
        prologue: &[u8],
        e: EphemeralSecret,
        re: PublicKey,
    ) -> Self {
        let mut symm_state = SymmState::init(b"Noise_NN_24419_ChaChaPoly_BLAKE2s");

        if prologue.len() > 0 {
            symm_state.mix_hash(prologue);
        }
        symm_state.mix_hash(re.as_bytes());
        Self {
            pattern,
            role,
            e,
            re,
        }
    }
}
