# TODO

Core platform work:

- [x] Make core nostd
- [x] make core generic over table types, so bounded and runtime-specific stores can be used.
- [ ] make sure everything is zeroized where needed (configurable by a feature)
- [ ] work out different session transports (streams etc)
- [ ] make sure tokio runtime can dynamically change all configuration while running, and then implement a declerative config + config/runtime reconcilliation
- [ ] can we reduce mtu overhead anywhere?

Application work:

- [ ] make a local network daemon
  - [ ] will use tokio interface
- [ ] work out daemon RPC capability broker architecture
  - [ ] broadly I want local network services (like DNS etc) to register capabilities with the network daemon so you can operate the entire network stack from one socket. will probably use cap'n proto
- [ ] work out initial protocol set (examples)
  - [ ] name resolution protocol
  - [ ] HTTP-over-sandalphon
  - [ ] TUN-over-sandalphon
  - [ ] some sort of native message protocol
  - [ ] probably gopher or something
  - [ ] (well probably actually a more simple any specific local port over sandalphon, and then TUN as an extension of that- would quite like to not roll my own SSH / wireguard etc)

Targets:

- [ ] make a binding crate with boltffi or something
- [ ] embassy runtime
  - [ ] work out a nice LoRa protocol shape (will probably need split-frames)
  - [ ] esp32 firmwares
- [ ] WASM runtime (might be possible to reuse binding crate with some modification to the tokio runtime)

Further research:

- [ ] protocol functionality
  - [ ] RTT estimation (using a kalman filter or something)
  - [ ] network tomography (for stuff like per-edge RTT estimation, identifying nodes that aren't transiting)
- [ ] STUN path upgrading protocol
- [ ] can we compress gossiped information more?
