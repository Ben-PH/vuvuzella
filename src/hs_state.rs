use blake2::digest::generic_array::GenericArray;
use bytes::BytesMut;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroize;

use crate::{cipher_state::CipherPair, symm_state::SymmState};

// key for AEAD cipher. spec gives AES256-GCM and chacha20-poly1305 as examples. 
#[derive(Zeroize)]
struct KeyPair(chacha20poly1305::Key);

struct HsState<'a> {
    prologue: &'a [u8],
    proto_name: &'a [u8],
    role: Role,
    symm_state: SymmState,
    other_pub: Option<PublicKey>,
    my_secret: EphemeralSecret,
    derived_shared: Option<SharedSecret>,
    pattern: Pattern,
}

impl<'a> HsState<'a> {
    pub fn start(pattern: Pattern, prologue: &'a [u8], proto_name: &'a [u8], role: Role) -> Self {
        let my_secret = EphemeralSecret::random();
        let mut symm_state = SymmState::init(proto_name);
        if !prologue.is_empty() {
            symm_state.mix_hash(prologue);
        }
        Self {
            prologue,
            proto_name,
            role,
            other_pub: None,
            my_secret,
            derived_shared: None,
            symm_state,
            pattern,
        }
    }

    pub fn write_e(&mut self, buff: &mut BytesMut) {
        let my_pub = PublicKey::from(&self.my_secret);
        self.symm_state.mix_hash(my_pub.as_bytes());
        buff.extend_from_slice(my_pub.as_bytes());
    }
    pub fn read_e(&mut self, re: PublicKey) {
        assert!(
            self.other_pub.is_none(),
            "Invariant broken: Reading remote `e` when remotes pubkey is already set"
        );
        self.symm_state.mix_hash(re.as_bytes());
        self.other_pub = Some(re);
    }

    pub fn init_with_ee(mut self) -> CipherPair {
        assert!(
            self.other_pub.is_some(),
            "Invariant broken: Initialising hs state without remotes pubkey"
        );
        let my_pub = PublicKey::from(&self.my_secret);
        let shared = self.my_secret.diffie_hellman(&self.other_pub.unwrap());
        let as_ga = &GenericArray::from_slice(shared.as_ref());
        self.symm_state.mix_key(as_ga);

        self.symm_state.consume()
    }
}

enum Secret {
    Shared(SharedSecret),
    Ephem(EphemeralSecret),
}

/// (Incomplete)
/// Fundamental patterns key:
/// # First character
/// N: **N**o static key for initiator
/// K: Static key for initiator **K**nown to responder
/// X: Static key for initiator **X**mitted to responder
/// I: Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent ID
/// hiding
///
/// # Second character
/// N: **N**o static key for responder
/// K: Static key for responder **K**nown to initiator
/// X: Static key for responder **X**mitted to initiator
#[non_exhaustive]
pub enum Pattern {
    // NN,
    XX,
    // NK,
    // KK,
}

impl Pattern {
    fn make_sequence(&self) -> Vec<Vec<TokenSet>> {
        match self {
            Pattern::XX => vec![vec![TokenSet::Key(KeyType::Ephemeral)]],
        }
    }
}

#[non_exhaustive]
enum KeyType {
    Ephemeral,
    // Static
}

struct DHPair {
    initiator: KeyType,
    responder: KeyType,
}

enum TokenSet {
    Key(KeyType),
    DH(DHPair),
}

pub enum Role {
    Initiator,
    Responder,
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    #[ignore = "this test needs to be fleshed out before beng consdered a green/go"]
    fn init_hs() {
        let proto_name = b"Noise_NN_24419_ChaChaPoly_BLAKE2s";
        let mut initer_bytes = BytesMut::new();
        let resper_bytes = BytesMut::new();
        let symm_state_ref = SymmState::init(proto_name);

        let mut hs_state_initer = HsState::start(Pattern::XX, &[], proto_name, Role::Initiator);
        let mut hs_state_resper = HsState::start(Pattern::XX, &[], proto_name, Role::Initiator);

        assert!(
            hs_state_initer.symm_state.eq(&symm_state_ref),
            "symmetric state not initiated correctly"
        );

        hs_state_initer.write_e(&mut initer_bytes);
        let pubkey_bytes: [u8; 32] = initer_bytes.as_ref()[0..32].try_into().unwrap();
        let resp_pub: PublicKey = PublicKey::from(pubkey_bytes);

        hs_state_resper.read_e(resp_pub);

        let channel = hs_state_resper.init_with_ee();
    }
}
