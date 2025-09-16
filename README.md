# PQC Handshake

Provides a protocol and net implementation to use post quantum cryptographic functions to prove ownership of keys and share a session key.

## Packets

### Structure
[Type {1 Byte}][UUID {16 Byte}][Timestamp {8 Byte}]

Where the highest bit of type denotes a fragmented packet when set and adds the following to the header:

[Fragment N.o. {1 Byte}][Fragment Count {1 Byte}]

All other internal fields are headed with an unsigned integer represented using the 
[github.com/1f349/int-byte-utils](https://github.com/1f349/int-byte-utils) package
signifying the length of the following filed.

### Types

#### 0) Reserved for future use

#### 1) Connection Rejected

#### 2) Initiate Packet
(Encapsulation data via Remote Public Key)(Local Public Key Hash)

Encapsulation can be empty to request the remote public key.
Local public key hash can be empty to signify local will send key.

#### 3) Initiate Proof Packet
(Encapsulation data via Remote Public Key)(HMAC using encapsulated key from local on the initiate packet bytes).

#### 4) Final Proof Packet
(HMAC using encapsulated key from remote on the initiate proof packet bytes)

#### 5) Public Key Request



#### 6) Public Key Data Packet
(Local/Remote Public key)

#### 7) Signature Request

#### 8) Public Key Signed Packet
(Signature of Public key using a signing key)(Hash of Signing Public Key)

#### 9) Signature Public Key Request

#### 10) Signed Packet Public Key
(Public Key for Signature)

#### 11-127) Reserved for future use

## Protocol


## License
BSD 3-Clause - (C) 1f349 2025
