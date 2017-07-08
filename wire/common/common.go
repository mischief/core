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

	"github.com/Katzenpost/noise"
)

const (
	// MaxPayloadSize is the maximum payload size permitted by wire protocol
	MaxPayloadSize = 65515
	// MessageSize is the size of a Message
	MessageSize = MaxPayloadSize + 4
	// MessageCiphertextSize is the size of the encrypted Message
	MessageCiphertextSize = MessageSize + 16
	// SphinxPacketSize is the Sphinx packet size
	SphinxPacketSize = 32768 // XXX: Yawning fix me
	// Ed25519KeySize is the size of an ed25519 key
	Ed25519KeySize = 32
	// PrologueSize is the size of our noise handshake prologue
	PrologueSize = 1
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

// Wire Protocol Commands
type commandID byte

const (
	noOp         commandID = 0x00
	disconnect   commandID = 0x01
	authenticate commandID = 0x02
	sendPacket   commandID = 0x03
)

// Message is a protocol message
type Message struct {
	command  commandID
	reserved byte
	length   uint16
	message  []byte
	padding  []byte
}

func MessageFromBytes(raw [MessageSize]byte) (*Message, error) {
	message := Message{}
	message.command = commandID(raw[0])
	message.reserved = raw[1]
	if message.reserved != byte(0) {
		return nil, errors.New("Message's reserved must be set to 0x00")
	}
	message.length = binary.LittleEndian.Uint16(raw[2:4])
	if message.length > MaxPayloadSize {
		return nil, fmt.Errorf("Message's length field %d exceeds MaxPayloadSize of %d",
			message.length, MaxPayloadSize)
	}
	message.message = raw[4 : 4+message.length]
	message.padding = raw[4+message.length:]
	return &message, nil
}

func (m *Message) ToBytes() ([MessageSize]byte, error) {
	out := [MessageSize]byte{}
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

func (m *Message) Encrypt(cs *noise.CipherState) (*Ciphertext, error) {
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

type Ciphertext struct {
	length     uint16
	ciphertext []byte
}

func CiphertextFromBytes(raw []byte) (*Ciphertext, error) {
	c := Ciphertext{}
	c.length = binary.LittleEndian.Uint16(raw[0:2])
	if c.length > MessageCiphertextSize {
		return nil, fmt.Errorf("%d exceeds max Ciphertext length of %d",
			c.length, MessageCiphertextSize)
	}
	c.ciphertext = raw[2:]
	return &c, nil
}

func (c *Ciphertext) Decrypt(cs *noise.CipherState) (*Message, error) {
	var plaintext [MessageSize]byte
	var out []byte
	var err error
	out, err = cs.Decrypt(out, nil, c.ciphertext)
	if err != nil {
		return nil, err
	}
	copy(plaintext[:], out)
	message, err := MessageFromBytes(plaintext)
	cs.Rekey()
	return message, err
}

func (c *Ciphertext) ToBytes() ([]byte, error) {
	out := make([]byte, c.length+2)
	binary.LittleEndian.PutUint16(out[:2], c.length)
	copy(out[2:], c.ciphertext)
	return out, nil
}
