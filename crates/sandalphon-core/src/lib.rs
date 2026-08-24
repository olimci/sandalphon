#![no_std]

extern crate alloc;

// Primatives!
pub mod crypto;
pub mod edge;
pub mod storage;

// Layers!
pub mod link; // Edge negotiation, gossip, one-hop-transport
pub mod network; // Multi-hop transport
pub mod session; // Encryption

// it's very pleasing how these OSI layers naturally fall in alphabetical order.
// for that reason we aren't allowed to have an application layer

// Network core
pub mod core;
