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
