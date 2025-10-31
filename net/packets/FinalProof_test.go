// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"crypto/sha256"
	"github.com/1f349/handshake/net/packets"
)

var ValidFinalProofPayload = &packets.FinalProofPayload{ProofHMAC: sha256.New().Sum(nil)}
var InvalidFinalProofPayload = &packets.FinalProofPayload{}
