// common.go - Common code for clients and servers of our wire protocol.
// Copyright (C) 2017  David Anthony Stainton
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

package common

import (
	"encoding/binary"
	"errors"
	"io"

	//"github.com/Katzenpost/core/utils"
	"github.com/Katzenpost/noise"
)

const (
	// MaxPayloadSize is the maximum payload size permitted by wire protocol
	MaxPayloadSize = 65515

	// messageMaxSize is the size of a message
	messageMaxSize = MaxPayloadSize + 4

	// messageCiphertextMaxSize is the size of the encrypted message
	// that is the "ciphertext" element of the Ciphertext struct
	messageCiphertextMaxSize = messageMaxSize + 16

	// SphinxPacketSize is the Sphinx packet size
	SphinxPacketSize = 32768 // XXX: Yawning fix me

	// ed25519KeySize is the size of an ed25519 key
	ed25519KeySize = 32

	// ed25519SignatureSize is the size of an ed25519 signature
	ed25519SignatureSize = 64

	// additionalDataSize is the size of additional data
	// in the authentication command
	additionalDataSize = 64

	// unixTimeSize is the size of a unix timestamp
	unixTimeSize = 4

	// noOpSize is the size of a serialized noOp command
	noOpSize = 10

	// disconnectSize is the size of a serialized disconnect command
	disconnectSize = 10

	// PrologueSize is the size of our noise handshake prologue
	prologueSize = 1

	// noOp is the no-operation command ID
	noOp commandID = 0x00

	// disconnect is the disconnect command ID
	disconnect commandID = 0x01

	// authenticate is the authenticate command ID
	authenticate commandID = 0x02

	// sendPacket is the sendPacket command ID
	sendPacket commandID = 0x03
)

// Session is an interface for implementing Client or Server protocols.
type Session interface {
	// Initiate should handle the session in a blocking manner
	// and return when the session is finished,
	// the Server/Client will subsequently close the connection.
	Initiate(conn io.ReadWriter) error
	Close() error
	Send(payload []byte) error
}

// Wire Protocol Command ID type
type commandID byte

var errInvalidCommand = errors.New("invalid wire protocol command")

// Command is the common interface exposed by all message
// command structures.
type Command interface {
	toBytes() []byte
}

type NoOpCommand struct{}

func (c NoOpCommand) toBytes() []byte {
	out := make([]byte, noOpSize)
	return out
}

type DisconnectCommand struct{}

func (c DisconnectCommand) toBytes() []byte {
	out := make([]byte, disconnectSize)
	return out
}

type AuthenticateCommand struct {
	PublicKey      [ed25519KeySize]byte
	Signature      [ed25519SignatureSize]byte
	AdditionalData [additionalDataSize]byte
	UnixTime       uint32
}

func (c AuthenticateCommand) toBytes() []byte {
	out := make([]byte, ed25519KeySize+ed25519SignatureSize+additionalDataSize+unixTimeSize)
	copy(out[0:], c.PublicKey[:])
	copy(out[ed25519KeySize:], c.Signature[:])
	copy(out[ed25519KeySize+ed25519SignatureSize:], c.AdditionalData[:])
	binary.LittleEndian.PutUint32(m[ed25519KeySize+ed25519SignatureSize+additionalDataSize:], c.UnixTime)
	return out
}

type SendPacketCommand struct {
	SphinxPacket [SphinxPacketSize]byte
}

func (c SendPacketCommand) toBytes() []byte {
	return c.SphinxPacket[:]
}

// CommandToCiphertextBytes converts Command
// structures to ciphertext bytes
func CommandToCiphertextBytes(cs *noise.CipherState, cmd Command) (ciphertext []byte) {
	raw := c.toPlaintextBytes()
	ciphertext = cs.Encrypt(ciphertext, nil, raw)
	cs.Rekey()
	return ciphertext
}

func FromBytes(raw []byte) (cmd Command, err error) {

}

// FromCiphertextBytes converts ciphertext
// bytes to Command structures
func FromCiphertextBytes(cs *noise.CipherState, ciphertext []byte) (cmd Command, err error) {
	var plaintext []byte
	plaintext, err = cs.Decrypt(plaintext, nil, ciphertext)
	cs.Rekey()
	if err != nil {
		return cmd, err
	}

	// XXX fix me

}
