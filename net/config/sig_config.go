package config

import "hash"

type SigConfig struct {
	Data    []byte
	Key     []byte
	keyHash []byte
}

// KeyHash generates from key data
func (sc *SigConfig) KeyHash(hash hash.Hash) []byte {
	if sc.keyHash == nil {
		hash.Reset()
		hash.Write(sc.Key)
		sc.keyHash = hash.Sum(nil)
	}
	return sc.keyHash
}
