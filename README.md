## Manage relay users gRPC Server
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)

# gRPC Extensions for nostr-rs-relay

gRPC authz server for [nostr-rs-rely](https://github.com/scsibug/nostr-rs-relay). Admits events based on whether they have been allowed by the relay admin.  

## Build and Run
This package is an extension of nostr-rs-relay and the instructions here assume the relay exists in `./nostr-rs-relay/`
1. Make sure you are running the latest version of Rust, if you installed with rustup:
```
rustup update
```
2. Clone and compile
```
git clone https://github.com/thesimplekid/manage-relay-users.git
cd manage-relay-users
cargo build -r
```
3. Edit the config file.
```
vim config.toml
```

Add a secret key.
Categorized People Lists from this key will update the allowed and denied users.
If the users are updated via http api this extension with publish an update list,
this enables the extension to restore from the lists stored on configured relays.

Uncomment the grpc and db_path lines.

4. Edit the config of the relay 
```
cd ../nostr-rs-relay
vim config.toml
```
Find the line with `event_admission_server`
```
[grpc]
# event_admission_server = "http://[::1]:50051" <---- this line
```
Uncomment this line and change it to reflect your local setup that matches the grpc config you used above. For example:
```
event_admission_server = "http://127.0.0.1:50001"
``` 
5. Run
You will need to use `screen` or `tmux` or a different terminal tab so that you can run two processes.
Start the relay manager first:
```
cd ../manage-relay-users
./target/release/manage_relay_users --config config.toml
```
In a different terminal on the same system:
```
cd ../nostr-rs-relay
RUST_LOG=warn,nostr_rs_relay=info ./target/release/nostr-rs-relay --config config.toml
```

## Managing Users

### Via Nostr

Allowed and Denied pubkeys are maintained in two [Categorized People Lists](https://github.com/nostr-protocol/nips/blob/master/51.md#categorized-people-list).
The nsec set in the config file is used by clients to publish list an `allow` list and a `deny` with the format set in [NIP-51](https://github.com/nostr-protocol/nips/blob/master/51.md).

### HTTP API

```

The users can be updated by sending a http `POST` to the  `/update` endpoint with a json body with the following format.
This extension with publish an updated Categorized People List with the updated users.

```json
{
    "allow":, [<32-bytes hex of a pubkey>,  <32-bytes hex of a pubkey>, ...],
    "deny": [<32-bytes hex of a pubkey>, <32-bytes hex of a pubkey>, ...],
}
```

There is also a `GET` endpoint with at `/users` that will return json of the same format with allowed and denied users.


If the relay has nip42 enabled it will use the authenticated pubkey if not the author pubkey of the note will be used. 


## License 
Code is under the [BSD 3-Clause License](LICENSE-BSD-3)

## Contact

I can be contacted for comments or questions on nostr at _@thesimplekid.com (npub1qjgcmlpkeyl8mdkvp4s0xls4ytcux6my606tgfx9xttut907h0zs76lgjw) or via email tsk@thesimplekid.com.
