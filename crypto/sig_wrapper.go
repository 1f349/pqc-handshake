// (C) 1f349 2025 - BSD-3-Clause License

package crypto

import (
	"github.com/1f349/handshake/crypto"
	"github.com/cloudflare/circl/sign"
	"sync"
)

var sigWrappedMap = make(map[sign.Scheme]*SigWrapper)
var slockSigWrappedMap = &sync.RWMutex{}

func getSigWrapper(scheme sign.Scheme) *SigWrapper {
	slockSigWrappedMap.RLock()
	defer slockSigWrappedMap.RUnlock()
	sigWrapped, ok := sigWrappedMap[scheme]
	if !ok {
		return nil
	}
	return sigWrapped
}

func addSigWrapper(scheme sign.Scheme) *SigWrapper {
	slockSigWrappedMap.Lock()
	defer slockSigWrappedMap.Unlock()
	if _, ok := sigWrappedMap[scheme]; !ok {
		sigWrappedMap[scheme] = &SigWrapper{scheme}
	}
	return sigWrappedMap[scheme]
}

// WrapSig a sign.Scheme
func WrapSig(scheme sign.Scheme) *SigWrapper {
	w := getSigWrapper(scheme)
	if w == nil {
		return addSigWrapper(scheme)
	}
	return w
}

// SigWrapper wraps sign.Scheme from github.com/cloudflare/circl for SigScheme
type SigWrapper struct {
	wrapped sign.Scheme
}

func (s SigWrapper) Name() string {
	return s.wrapped.Name()
}

func (s SigWrapper) GenerateKeyPair() (crypto.SigPublicKey, crypto.SigPrivateKey, error) {
	p, q, err := s.wrapped.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return &SigPublicKeyWrapper{p}, &SigPrivateKeyWrapper{q}, nil
}

func (s SigWrapper) UnmarshalBinaryPrivateKey(bytes []byte) (crypto.SigPrivateKey, error) {
	wk, err := s.wrapped.UnmarshalBinaryPrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return &SigPrivateKeyWrapper{wk}, nil
}

func (s SigWrapper) UnmarshalBinaryPublicKey(bytes []byte) (crypto.SigPublicKey, error) {
	wk, err := s.wrapped.UnmarshalBinaryPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return &SigPublicKeyWrapper{wk}, nil
}

func (s SigWrapper) Sign(key crypto.SigPrivateKey, msg []byte) (stxt []byte, err error) {
	if wk, ok := key.(*SigPrivateKeyWrapper); ok {
		defer func() {
			if r := recover(); r != nil {
				if e, ok := r.(error); ok {
					err = e
				} else {
					panic(r)
				}
			}
		}()
		return s.wrapped.Sign(wk.PrivateKey, msg, nil), nil
	}
	return nil, ErrIncompatibleKey
}

func (s SigWrapper) Verify(key crypto.SigPublicKey, msg []byte, sig []byte) (v bool, err error) {
	if wk, ok := key.(*SigPublicKeyWrapper); ok {
		defer func() {
			if r := recover(); r != nil {
				if e, ok := r.(error); ok {
					err = e
				} else {
					panic(r)
				}
			}
		}()
		return s.wrapped.Verify(wk.PublicKey, msg, sig, nil), nil
	}
	return false, ErrIncompatibleKey
}

func (s SigWrapper) PublicKeySize() int {
	return s.wrapped.PublicKeySize()
}

func (s SigWrapper) PrivateKeySize() int {
	return s.wrapped.PrivateKeySize()
}

func (s SigWrapper) SignatureSize() int {
	return s.wrapped.SignatureSize()
}

// SigPublicKeyWrapper wraps sign.PublicKey  for SigPublicKey
type SigPublicKeyWrapper struct {
	sign.PublicKey
}

func (k SigPublicKeyWrapper) Scheme() crypto.SigScheme {
	return getSigWrapper(k.PublicKey.Scheme())
}

func (k SigPublicKeyWrapper) Equals(key crypto.SigPublicKey) bool {
	if wk, ok := key.(*SigPublicKeyWrapper); ok {
		return k.PublicKey.Equal(wk.PublicKey)
	}
	if wk, ok := key.(SigPublicKeyWrapper); ok {
		return k.PublicKey.Equal(wk.PublicKey)
	}
	return false
}

// SigPrivateKeyWrapper wraps sign.PrivateKey for SigPrivateKey
type SigPrivateKeyWrapper struct {
	sign.PrivateKey
}

func (k SigPrivateKeyWrapper) Scheme() crypto.SigScheme {
	return getSigWrapper(k.PrivateKey.Scheme())
}

func (k SigPrivateKeyWrapper) Equals(key crypto.SigPrivateKey) bool {
	if wk, ok := key.(*SigPrivateKeyWrapper); ok {
		return k.PrivateKey.Equal(wk.PrivateKey)
	}
	if wk, ok := key.(SigPrivateKeyWrapper); ok {
		return k.PrivateKey.Equal(wk.PrivateKey)
	}
	return false
}

func (k SigPrivateKeyWrapper) Public() crypto.SigPublicKey {
	if ak, ok := k.PrivateKey.Public().(sign.PublicKey); ok {
		return &SigPublicKeyWrapper{ak}
	}
	return nil
}
