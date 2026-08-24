# Sandalphon

My attempt at building a simple encrypted mesh routing protocol. The architecture is based vaguely on SCION and MPLS. Made as an experiment, since I found other mesh routing protocols, _cough cough reticulum cough cough_, to have a bunch of flaws that I figured I might be able to fix with a better architecture.

Each peer uses a single secp256k1[^1] static private key for identity and encryption, and it uses that to make mutually-signed edges between peers. These edges are then composed to form routes between peers.

Packets are then routed with a path-label-switching header. Specifically for some outbound packet with path labal `AD` (A-B-C-D), you extract the first edge `A`, giving you the egress interface `A` and the next path label `BD` (B-C-D).

Sandalphon handles encryption using per-connection sessions between peers. Specically a custom noise scheme `Noise_IK_secp256k1_ChaCha20Poly1305_SHA256`.

Overall, it gives you online routing, path-addressability, some relatively good guarantees for being able to reach remote peers, even on networks with malicious actors. The path-label-switching header gives you fixed packet header sizes over arbitrarily long paths too, which is nice.

The project is still very much WIP. look [here](TODO.md) to see what I'm still working on.

[^1]: I decided on this, since it allows me to reuse the same key for signing and encryption. Other protocols use a pair of ed25519 and x25519 keys, which doubles the byte-overhead of each key which I wanted to avoid. Also secp256k1 is cool.
