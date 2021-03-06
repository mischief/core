// eddsa.go - EdDSA wrappers.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package eddsa provides EdDSA (Ed25519) wrappers.
package eddsa

import (
	"encoding/base64"
	"errors"
	"io"

	"github.com/katzenpost/core/utils"
	"golang.org/x/crypto/ed25519"
)

const (
	// PublicKeySize is the size of a serialized PublicKey in bytes (32 bytes).
	PublicKeySize = ed25519.PublicKeySize

	// PrivateKeySize is the size of a serialized PrivateKey in bytes (64 bytes).
	PrivateKeySize = ed25519.PrivateKeySize

	// SignatureSize is the size of a serialized Signature in bytes (64 bytes).
	SignatureSize = ed25519.SignatureSize
)

var errInvalidKey = errors.New("eddsa: invalid key")

// PublicKey is a EdDSA public key.
type PublicKey struct {
	pubKey ed25519.PublicKey
}

// Bytes returns the raw public key.
func (k *PublicKey) Bytes() []byte {
	return k.pubKey
}

// FromBytes deserializes the byte slice b into the PublicKey.
func (k *PublicKey) FromBytes(b []byte) error {
	if len(b) != PublicKeySize {
		return errInvalidKey
	}

	k.pubKey = make([]byte, PublicKeySize)
	copy(k.pubKey, b)
	return nil
}

// MarshalBinary implements the BinaryMarshaler interface
// defined in https://golang.org/pkg/encoding/
func (k *PublicKey) MarshalBinary() ([]byte, error) {
	return k.Bytes(), nil
}

// UnmarshalBinary implements the BinaryUnmarshaler interface
// defined in https://golang.org/pkg/encoding/
func (k *PublicKey) UnmarshalBinary(data []byte) error {
	return k.FromBytes(data)
}

// MarshalText implements the TextMarshaler interface
// defined in https://golang.org/pkg/encoding/
func (k *PublicKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(k.Bytes())), nil
}

// UnmarshalText implements the TextUnmarshaler interface
// defined in https://golang.org/pkg/encoding/
func (k *PublicKey) UnmarshalText(data []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	return k.FromBytes(raw)
}

// Reset clears the PublicKey structure such that no sensitive data is left in
// memory.  PublicKeys, despite being public may be considered sensitive in
// certain contexts (eg: if used once in path selection).
func (k *PublicKey) Reset() {
	utils.ExplicitBzero(k.pubKey)
}

// Verify returns true iff the signature sig is valid for the message msg.
func (k *PublicKey) Verify(sig, msg []byte) bool {
	return ed25519.Verify(k.pubKey, msg, sig)
}

// PrivateKey is a EdDSA private key.
type PrivateKey struct {
	pubKey  PublicKey
	privKey ed25519.PrivateKey
}

// FromBytes deserializes the byte slice b into the PrivateKey.
func (k *PrivateKey) FromBytes(b []byte) error {
	if len(b) != PrivateKeySize {
		return errInvalidKey
	}

	k.privKey = make([]byte, PrivateKeySize)
	copy(k.privKey, b)
	k.pubKey.pubKey = k.privKey.Public().(ed25519.PublicKey)
	return nil
}

// Bytes returns the raw private key.
func (k *PrivateKey) Bytes() []byte {
	return k.privKey
}

// Reset clears the PrivateKey structure such that no sensitive data is left
// in memory.
func (k *PrivateKey) Reset() {
	k.pubKey.Reset()
	utils.ExplicitBzero(k.privKey)
}

// PublicKey returns the PublicKey corresponding to the PrivateKey.
func (k *PrivateKey) PublicKey() *PublicKey {
	return &k.pubKey
}

// Sign signs the message msg with the PrivateKey and returns the signature.
func (k *PrivateKey) Sign(msg []byte) []byte {
	return ed25519.Sign(k.privKey, msg)
}

// NewKeypair generates a new PrivateKey sampled from the provided entropy
// source.
func NewKeypair(r io.Reader) (*PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}

	k := new(PrivateKey)
	k.privKey = privKey
	k.pubKey.pubKey = pubKey
	return k, nil
}
