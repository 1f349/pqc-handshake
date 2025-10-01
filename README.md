# PQC Handshake

Provides a protocol and net implementation to use post quantum cryptographic functions to prove ownership of keys and share a session key.
The architecture of the library allows for the use of the use of any compatible algorithms for key encapsulation, HMAC, hashing and signing.
This can even include providing a capabilities packet for negotiating those aforementioned algorithms (Hence ID 0 has been reserved for this).

Proving key ownership is as simple as sending the encapsulated symmetric key to the other node, 
with a HMAC of the previous packet bytes 
(Using the key derived from the encapsulation of that packet) 
but only if this is not the initiator packet. 
When receiving a packet confirm the provided HMAC (If there is one) is correct 
(The expected HMAC is calculated before the packet is sent to the other side). 
This proves key ownership as only the private key owner can de-encapsulate the sent encapsulation and use it for the HMAC. 
The encapsulated key also serves as a nonce due to its guaranteed randomisation due to the way KEMs work with deriving a new random key. 

A key derived using the wrong private key can, depending on the KEM implementation, negligibly collide with the actual encapsulated key, 
thereby failing the proof check (A probability equal to 1/[Number of possible keys]). 

The signatures are performed over a hashed form of the data they are signing, 
which also have a much higher, but still negligible chance of collision, 
with other valid data (Due to hashes being shorter than the input data therefore having less entropy)
snd is mitigated via specifying the use of a 'collision-resistant' hash function.

## Packets

### Format Key

[Byte Array {Array Length}]

(Variable uint)

([] Variable byte array headed by variable uint)

? means any positive size

### Structure
[Type {1 Byte}] [UUID {16 Byte}] [Timestamp {8 Byte}]

Where the highest bit of type denotes a fragmented packet when set and adds the following to the header:

[Fragment N.o. {1 Byte}] [Fragment Count {1 Byte}]

All other internal fields,, that are byte arrays, 
are headed with an unsigned integer represented using the 
[github.com/1f349/int-byte-utils](https://github.com/1f349/int-byte-utils) package
signifying the length of the following field, where these are denoted as ([] Field), 
if only an unsigned integer is represented, this is denoted as (Field).

### Types

#### 0) Reserved for future use

Could be used by the user for negotiation of algorithms to be used.

#### 1) Connection Rejected

#### 2) Initiate Packet
([] Encapsulation data via Remote Public Key) ([] Local Public Key Hash)

(A) Encapsulation can be empty to request the remote public key.
(B) Local public key hash can be empty to signify that local should be asked to send key.

#### 3) Initiate Proof Packet
([] Encapsulation data via Remote Public Key) ([] HMAC using encapsulated key from local on the initiate packet bytes)

#### 4) Final Proof Packet
([] HMAC using encapsulated key from remote on the initiate proof packet bytes)

#### 5) Public Key Request

#### 6) Public Key Data Packet
([] Local/Remote Public key)

#### 7) Signature Request

#### 8) Public Key Signed Packet
([] Signature Data) ([] Hash of Signing Public Key)

#### 9) Signature Public Key Request

#### 10) Signed Packet Public Key
([] Public Key for Signature)

#### 11-31) Reserved for future use

#### 32-127) Reserved for user extended use

## Protocol

### Signature Format

Signature is a byte array represented as base64 when being used in configuration data.

#### Signed Data

[Public Key {? Bytes}] (Issue Time) (Expiry Time) -> Hashed

#### Signature Data

(Signature Length) [Signature {Signature Length}] (Issue Time) (Expiry Time)

### List of Flows

## License
BSD 3-Clause - (C) 1f349 2025
