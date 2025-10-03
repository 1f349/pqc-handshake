package config

import (
	"github.com/1f349/pqc-handshake/crypto"
	"hash"
)

type NodeConfig struct {
	KEM             crypto.KemScheme
	HMACHash        hash.Hash
	KeySigCheckHash hash.Hash
}
