// (C) 1f349 2025 - BSD-3-Clause License

package config

import (
	"github.com/1f349/pqc-handshake/crypto"
	"hash"
)

type SigVerifierConfig struct {
	SigDataHash   hash.Hash
	Scheme        crypto.SigScheme
	PublicKeyData []byte
	publicKeyHash []byte
	publicKey     crypto.SigPublicKey
	// LastError is the cause of the last failure of PublicKey generation
	LastError error
}

// PublicKeyHash generates from public key data
func (svc *SigVerifierConfig) PublicKeyHash(hash hash.Hash) []byte {
	if svc.publicKeyHash == nil {
		hash.Reset()
		hash.Write(svc.PublicKeyData)
		svc.publicKeyHash = hash.Sum(nil)
	}
	return svc.publicKeyHash
}

// PublicKey constructed from public key data, nil on failure
// LastError contains the error that caused a failure
func (svc *SigVerifierConfig) PublicKey() crypto.SigPublicKey {
	if svc.publicKey == nil {
		var err error
		svc.publicKey, err = svc.Scheme.UnmarshalBinaryPublicKey(svc.PublicKeyData)
		if err != nil {
			svc.LastError = err
			return nil
		}
	}
	return svc.publicKey
}
