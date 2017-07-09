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
	"fmt"
	"io"

	"github.com/Katzenpost/core/utils"
	"github.com/Katzenpost/noise"
)

const (
	// MaxPayloadSize is the maximum payload size permitted by wire protocol
	MaxPayloadSize = 65515

	// messageOverhead is the number of bytes before the message's payload
	messageOverhead = 4

	// messageMaxSize is the size of a message
	messageMaxSize = MaxPayloadSize + messageOverhead

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

	// authCmdSize is the size of the authenticate command
	authCmdSize = ed25519KeySize + ed25519SignatureSize + additionalDataSize + unixTimeSize

	// reserved is a reserved section of the serialized commands
	reserved = byte(0)

	// noOpSize is the size of a serialized noOp command
	noOpSize = uint16(10)

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
	out := make([]byte, messageOverhead+noOpSize)
	out[0] = byte(noOp)
	return out
}

type DisconnectCommand struct{}

func (c DisconnectCommand) toBytes() []byte {
	out := make([]byte, messageOverhead+disconnectSize)
	out[0] = byte(disconnect)
	return out
}

type AuthenticateCommand struct {
	PublicKey      [ed25519KeySize]byte
	Signature      [ed25519SignatureSize]byte
	AdditionalData [additionalDataSize]byte
	UnixTime       uint32
}

func (c AuthenticateCommand) toBytes() []byte {
	out := make([]byte, messageOverhead+authCmdSize)
	out[0] = byte(authenticate)
	out[1] = reserved
	binary.BigEndian.PutUint16(out[2:4], authCmdSize)
	copy(out[4:], c.PublicKey[:])
	copy(out[4+ed25519KeySize:], c.Signature[:])
	copy(out[4+ed25519KeySize+ed25519SignatureSize:], c.AdditionalData[:])
	binary.BigEndian.PutUint32(out[4+ed25519KeySize+ed25519SignatureSize+additionalDataSize:], c.UnixTime)
	return out
}

type SendPacketCommand struct {
	SphinxPacket [SphinxPacketSize]byte
}

func (c SendPacketCommand) toBytes() []byte {
	out := make([]byte, messageOverhead+SphinxPacketSize)
	out[0] = byte(sendPacket)
	out[1] = reserved
	binary.BigEndian.PutUint16(out[2:4], SphinxPacketSize)
	copy(out[4:], c.SphinxPacket[:])
	return out
}

// CommandToCiphertextBytes converts Command
// structures to ciphertext bytes
func CommandToCiphertextBytes(cs *noise.CipherState, cmd Command) (ciphertext []byte) {
	raw := cmd.toBytes()
	ciphertext = cs.Encrypt(ciphertext, nil, raw)
	cs.Rekey()
	return ciphertext
}

// fromBytes converts a byte slice to a command structure
func fromBytes(raw []byte) (Command, error) {
	cmd := raw[0]
	raw = raw[1:]
	switch commandID(cmd) {
	case noOp:
		if len(raw) != int(noOpSize+messageOverhead-1) {
			return nil, errInvalidCommand
		}
		if !utils.CtIsZero(raw) {
			return nil, errInvalidCommand
		}
		return new(NoOpCommand), nil
	case disconnect:
		if len(raw) != disconnectSize+messageOverhead-1 {
			return nil, errInvalidCommand
		}
		if !utils.CtIsZero(raw) {
			return nil, errInvalidCommand
		}
		return new(DisconnectCommand), nil
	case authenticate:
		if len(raw) != authCmdSize+messageOverhead-1 {
			return nil, errInvalidCommand
		}
		if raw[0] != byte(0) {
			return nil, errInvalidCommand
		}
		cmd := new(AuthenticateCommand)
		//size := binary.BigEndian.Uint16(raw[1:3]) // XXX should we bother with this?
		raw = raw[3:]
		copy(cmd.PublicKey[:], raw[:ed25519KeySize])
		copy(cmd.Signature[:], raw[ed25519KeySize:ed25519SignatureSize])
		copy(cmd.AdditionalData[:], raw[ed25519KeySize+ed25519SignatureSize:])
		cmd.UnixTime = binary.BigEndian.Uint32(raw[ed25519KeySize+ed25519SignatureSize+additionalDataSize:])
		return cmd, nil
	case sendPacket:
		if len(raw) != SphinxPacketSize+messageOverhead-1 {
			return nil, errInvalidCommand
		}
		if raw[0] != byte(0) {
			return nil, errInvalidCommand
		}
		cmd := new(SendPacketCommand)
		//size := binary.BigEndian.Uint16(raw[1:3]) // XXX should we bother with this?
		raw = raw[3:]
		copy(cmd.SphinxPacket[:], raw)
		return cmd, nil
	default:
		return nil, errInvalidCommand
	}
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
	cmd, err = fromBytes(plaintext)
	return cmd, err
}

func ReceiveCommand(cs *noise.CipherState, conn io.Reader) (Command, error) {
	rawLen := make([]byte, 2)
	_, err := io.ReadFull(conn, rawLen)
	if err != nil {
		return nil, err
	}

	ciphertextLen := binary.BigEndian.Uint16(rawLen[0:2])
	ciphertext := make([]byte, ciphertextLen)
	_, err = io.ReadFull(conn, ciphertext)
	if err != nil {
		return nil, err
	}

	cmd, err := FromCiphertextBytes(cs, ciphertext)
	return cmd, err
}

func SendPacket(cmd Command, cs *noise.CipherState, conn io.Writer) error {
	ciphertext := CommandToCiphertextBytes(cs, cmd)
	ciphertextLen := len(ciphertext)
	packet := make([]byte, ciphertextLen+2)
	binary.BigEndian.PutUint16(packet[0:2], uint16(ciphertextLen))
	copy(packet[2:], ciphertext)

	count, err := conn.Write(packet)
	if err != nil {
		return err
	}
	if count != len(packet) {
		return fmt.Errorf("failed to send entire packet: %d != %d", count, len(packet))
	}
	return nil
}
