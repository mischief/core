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

	// messageSize is the size of a message
	messageSize = MaxPayloadSize + 4

	// messageCiphertextMaxSize is the size of the encrypted message
	// that is the "ciphertext" element of the Ciphertext struct
	messageCiphertextMaxSize = messageSize + 16

	// SphinxPacketSize is the Sphinx packet size
	SphinxPacketSize = 32768 // XXX: Yawning fix me

	// Ed25519KeySize is the size of an ed25519 key
	Ed25519KeySize = 32

	// PrologueSize is the size of our noise handshake prologue
	PrologueSize = 1

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

// message is a protocol message
type message struct {
	command  commandID
	reserved byte
	length   uint16
	message  []byte
	padding  []byte
}

// messageFromBytes is used to get a message struct
// given a slice of bytes
func messageFromBytes(raw [messageSize]byte) (*message, error) {
	message := message{}
	message.command = commandID(raw[0])
	message.reserved = raw[1]
	if message.reserved != byte(0) {
		return nil, errors.New("message's reserved must be set to 0x00")
	}
	message.length = binary.LittleEndian.Uint16(raw[2:4])
	if message.length > MaxPayloadSize {
		return nil, fmt.Errorf("message's length field %d exceeds MaxPayloadSize of %d",
			message.length, MaxPayloadSize)
	}
	message.message = raw[4 : 4+message.length]
	message.padding = raw[4+message.length:]
	if !utils.CtIsZero(message.padding) {
		return nil, errors.New("message's padding must be all 0x00 bytes")
	}
	return &message, nil
}

// ToBytes converts a message into a byte array
func (m *message) ToBytes() ([messageSize]byte, error) {
	out := [messageSize]byte{}
	if !utils.CtIsZero(m.padding) {
		return out, errors.New("message's padding must be all 0x00 bytes")
	}
	if m.reserved != byte(0) {
		return out, errors.New("reserved not set to 0x00")
	}
	if int(m.length) != len(m.message) || int(m.length) > MaxPayloadSize {
		return out, fmt.Errorf("incorrect length %d %d", int(m.length), len(m.message))
	}
	out[0] = byte(m.command)
	out[1] = m.reserved
	binary.LittleEndian.PutUint16(out[2:4], m.length)
	copy(out[4:4+m.length], m.message)
	copy(out[4+m.length:], m.padding)
	return out, nil
}

// Encrypt encrypts a message returning a Ciphertext
func (m *message) Encrypt(cs *noise.CipherState) (*Ciphertext, error) {
	raw, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	var out []byte
	out = cs.Encrypt(out, nil, raw[:])
	cs.Rekey()
	ciphertext := Ciphertext{
		length:     uint16(len(out)),
		ciphertext: out,
	}
	return &ciphertext, nil
}

// Ciphertext represents an encrypted message
type Ciphertext struct {
	length     uint16
	ciphertext []byte
}

// CiphertextFromBytes converts bytes to Ciphertext struct
func CiphertextFromBytes(raw []byte) (*Ciphertext, error) {
	c := Ciphertext{}
	c.length = binary.LittleEndian.Uint16(raw[0:2])
	c.ciphertext = raw[2:]
	if int(c.length) != len(c.ciphertext) {
		return nil, fmt.Errorf("%d is incorrect Ciphertext length", c.length)
	}
	return &c, nil
}

// Decrypt decrypts Ciphertext into a message
func (c *Ciphertext) Decrypt(cs *noise.CipherState) (*message, error) {
	var plaintext [messageSize]byte
	var out []byte
	var err error
	out, err = cs.Decrypt(out, nil, c.ciphertext)
	if err != nil {
		return nil, err
	}
	copy(plaintext[:], out)
	message, err := messageFromBytes(plaintext)
	cs.Rekey()
	return message, err
}

// ToBytes converts a Ciphertext struct into a byte slice
func (c *Ciphertext) ToBytes() ([]byte, error) {
	if int(c.length) != len(c.ciphertext) {
		return nil, fmt.Errorf("%d is incorrenct Ciphertext length", c.length)
	}
	out := make([]byte, int(c.length)+2)
	binary.LittleEndian.PutUint16(out, c.length)
	copy(out[2:], c.ciphertext)
	return out, nil
}

// MessageCommand is the common interface exposed by all message
// command structures.
type MessageCommand interface {
	toMessage() *message
}

type NoOpCommand struct{}

func (c NoOpCommand) toMessage() *message {
	m := message{
		command:  noOp,
		reserved: byte(0),
		length:   uint16(0),
		message:  []byte{},
		padding:  make([]byte, messageSize),
	}
	return &m
}

type DisconnectCommand struct{}

func (c DisconnectCommand) toMessage() *message {
	m := message{
		command:  disconnect,
		reserved: byte(0),
		length:   uint16(0),
		message:  []byte{},
		padding:  make([]byte, messageSize),
	}
	return &m
}

type AuthenticateCommand struct {
	PublicKey      [32]byte
	Signature      [64]byte
	AdditionalData [64]byte
	UnixTime       uint32
}

func (c AuthenticateCommand) toMessage() *message {
	m := make([]byte, 24)
	copy(m[0:], c.PublicKey[:])
	copy(m[4:], c.Signature[:])
	copy(m[13:], c.AdditionalData[:])
	binary.LittleEndian.PutUint32(m[22:], c.UnixTime)
	message := message{
		command:  authenticate,
		reserved: byte(0),
		length:   24,
		message:  []byte{},
		padding:  make([]byte, messageSize-24),
	}
	return &message
}

type SendPacketCommand struct {
	SphinxPacket [SphinxPacketSize]byte
}

func (c SendPacketCommand) toMessage() *message {
	m := message{
		command:  sendPacket,
		reserved: byte(0),
		length:   uint16(SphinxPacketSize),
		message:  c.SphinxPacket[:],
		padding:  make([]byte, messageSize-SphinxPacketSize),
	}
	return &m
}

// CommandFromMessage converts a message into a Command
func CommandFromMessage(m *message) (cmd MessageCommand, err error) {
	switch m.command {
	case noOp:
		if m.length != 0 || len(m.message) != 0 || len(m.padding) != messageSize {
			cmd = nil
			err = errors.New("invalid noOp command")
		} else {
			cmd = &NoOpCommand{}
		}
	case disconnect:
		if m.length != 0 || len(m.message) != 0 || len(m.padding) != messageSize {
			cmd = nil
			err = errors.New("invalid disconnect command")
		} else {
			cmd = &DisconnectCommand{}
		}
	case authenticate:
		auth := AuthenticateCommand{}
		copy(auth.PublicKey[:], m.message[0:4])
		copy(auth.Signature[:], m.message[4:12])
		copy(auth.AdditionalData[:], m.message[12:20])
		auth.UnixTime = binary.LittleEndian.Uint32(m.message[20:])
		cmd = &auth
	case sendPacket:
		if len(m.message) != SphinxPacketSize {
			err = errors.New("invalid Sphinx command")
		} else {
			s := SendPacketCommand{}
			copy(s.SphinxPacket[:], m.message)
			cmd = &s
		}
	default:
		err = errInvalidCommand
	}
	return
}

// CommandFromCiphertextBytes converts ciphertext bytes to
// MessageCommand structures by first converting to a Ciphertext struct
// and then decrypting to a message structure and finally converting
// to a MessageCommand structure
func CommandFromCiphertextBytes(cs *noise.CipherState, rawCiphertext []byte) (cmd MessageCommand, err error) {
	ciphertext, err := CiphertextFromBytes(rawCiphertext)
	if err != nil {
		return cmd, err
	}
	message, err := ciphertext.Decrypt(cs)
	if err != nil {
		return cmd, err
	}
	cmd, err = CommandFromMessage(message)
	return cmd, err
}

// CommandToCiphertextBytes converts MessageCommand structures to
// ciphertext bytes by first converting to a message struct and then
// encrypting to a Ciphertext struct
func CommandToCiphertextBytes(cs *noise.CipherState, cmd MessageCommand) ([]byte, error) {
	message := cmd.toMessage()
	ciphertext, err := message.Encrypt(cs)
	if err != nil {
		return nil, err
	}
	rawCiphertext, err := ciphertext.ToBytes()
	return rawCiphertext, err
}
