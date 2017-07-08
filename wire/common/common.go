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
)

const (
	// MaxPayloadSize is the maximum payload size permitted by wire protocol
	MaxPayloadSize = 65515
	MessageSize    = MaxPayloadSize + 4
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

func FromBytes(raw [MessageSize]byte) (*Message, error) {
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
