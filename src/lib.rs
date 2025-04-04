// TODO: as part of making this library usable, remove these dead-code allows.
#![allow(unused_variables)]
#![allow(dead_code)]
/// One each during handshake. During transport, each has one for sending, one for recieving
pub mod cipher_state;
/// Contains a symetric state, plus the diffie-helmen variables.
/// Deleted once handshake is complete.
pub mod hs_state;
pub mod nonce;
/// Contains cipher_state + ck and h variables. Each parties sole symm_state encapsulates the
/// "symmetric cryptography" used by Noise.
/// Deleted once handshake is complete.
pub mod symm_state;



// TODO: encapsulate these qualities within the type system
// A transport message is an AEAD ciphertext <= u16::MAX len.
// contains cipher-text plus 16 bytes of auth-data
//
// A handshake message is u16::MAX len. it begins with >= 1 DH pub keys (msg pattern determined),
// then followed by the payload.


// TODO: Implement a PoC executable that uses basic patterns, then use that to insta-snapshot test

