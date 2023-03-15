## Manage relay users gRPC Server
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)

# gRPC Extensions for nostr-rs-relay

gRPC authz server for [nostr-rs-rely](https://github.com/scsibug/nostr-rs-relay). Admits events based on whether they have been allowed by the relay admin.  The admin(s) can update accounts by publishing an `kind` 4242 event with an allow tag where index 0 is "allow" followed by the list of hex pubkeys, and a "deny" tag of the same format. Or by posting to the http endpoint (unimplemented)
 
For now this is not in a NIP if there is interest it can be more formalized.

Events can be published using this branch of nostr tools or implementing the event format in other tools.

https://github.com/thesimplekid/nostr-tool/tree/manage_relay_users

```json
{
  "id": <32-bytes lowercase hex-encoded sha256 of the the serialized event data>,
  "pubkey": <pubkey of the relay admin>,
  "created_at": <unix timestamp in seconds>,
  "kind": 4242,
  "tags": [
    ["allow", <32-bytes hex of a pubkey>,  <32-bytes hex of a pubkey>, ...],
    ["deny", <32-bytes hex of a pubkey>, <32-bytes hex of a pubkey>, ...],
    ...
  ],
  "content": "", 
  ...
}

```

If the relay has nip42 enabled it will use the authenticated pubkey if not the author pubkey of the note will be used. 


## License 
Code is under the [BSD 3-Clause License](LICENSE-BSD-3)

## Contact

I can be contacted for comments or questions on nostr at _@thesimplekid.com (npub1qjgcmlpkeyl8mdkvp4s0xls4ytcux6my606tgfx9xttut907h0zs76lgjw) or via email tsk@thesimplekid.com.
