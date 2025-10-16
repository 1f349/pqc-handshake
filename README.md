# PQC Handshake

This provides wrapper around [github.com/cloudflare/circl](https://github.com/cloudflare/circl) package for use with 
the [github.com/1f349/handshake](https://github.com/1f349/handshake) package which provides the protocol.

Documentation and implementation of the handshake is located there and the package located here allows usage (Via wrapping the Cloudflare library)
of post quantum cryptographic functions to prove ownership of keys and share a session key.

This also provides the tests utilizing MLK-KEM-78 and ML-DSA-44 algorithms.

## License
BSD 3-Clause - (C) 1f349 2025
