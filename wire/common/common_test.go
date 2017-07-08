// common_test.go - Tests for common code of the noise based wire protocol.
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToBytesMessageFromBytes(t *testing.T) {
	assert := assert.New(t)

	padding := [MaxPayloadSize - 5]byte{}
	message1 := Message{
		command:  noOp,
		reserved: byte(0),
		length:   uint16(5),
		message:  []byte("hello"),
		padding:  padding[:],
	}
	raw1, err := message1.ToBytes()
	assert.NoError(err, "ToBytes failed")
	message2, err := MessageFromBytes(raw1)
	assert.NoError(err, "MessageFromBytes failed")
	assert.Equal(message1.message, message2.message, "message not equal")
	raw2, err := message2.ToBytes()
	assert.NoError(err, "ToBytes failed")
	assert.Equal(raw1, raw2, "byte slices not equal")
}

func TestToBytesIncorrectLength(t *testing.T) {
	assert := assert.New(t)

	padding := [MaxPayloadSize - 5]byte{}
	message1 := Message{
		command:  noOp,
		reserved: byte(0),
		length:   uint16(MaxPayloadSize + 2),
		message:  []byte("hello"),
		padding:  padding[:],
	}
	_, err := message1.ToBytes()
	assert.Error(err, "ToBytes should have failed")
}

func TestMessageFromBytesIncorrectLength(t *testing.T) {
	assert := assert.New(t)

	padding := [MaxPayloadSize - 5]byte{}
	message1 := Message{
		command:  noOp,
		reserved: byte(0),
		length:   uint16(5),
		message:  []byte("hello"),
		padding:  padding[:],
	}
	raw1, err := message1.ToBytes()
	binary.LittleEndian.PutUint16(raw1[2:4], MaxPayloadSize+1)
	_, err = MessageFromBytes(raw1)
	assert.Error(err, "MessageFromBytes should have failed")
}

func TestMessageFromBytesIncorrectReserved(t *testing.T) {
	assert := assert.New(t)

	padding := [MaxPayloadSize - 5]byte{}
	message1 := Message{
		command:  noOp,
		reserved: byte(0),
		length:   uint16(5),
		message:  []byte("hello"),
		padding:  padding[:],
	}
	raw1, err := message1.ToBytes()
	assert.NoError(err, "ToBytes failed")
	raw1[1] = 1
	message2, err := MessageFromBytes(raw1)
	assert.Error(err, "MessageFromBytes should have failed")
	assert.Nil(message2, nil, "message should be nil")
}

func TestToBytesIncorrectReserved(t *testing.T) {
	assert := assert.New(t)

	padding := [MaxPayloadSize - 5]byte{}
	message1 := Message{
		command:  noOp,
		reserved: byte(1),
		length:   uint16(5),
		message:  []byte("hello"),
		padding:  padding[:],
	}
	_, err := message1.ToBytes()
	assert.Error(err, "ToBytes should have failed")
}

func TestCiphertextToBytesCiphertextFromBytes(t *testing.T) {
	assert := assert.New(t)

	c1 := Ciphertext{
		length:     5,
		ciphertext: []byte("hello"),
	}
	b1, err := c1.ToBytes()
	assert.NoError(err, "ToBytes should not have errored")
	c2, err := CiphertextFromBytes(b1)
	assert.NoError(err, "CiphertextFromBytes should not have errored")
	b2, err := c2.ToBytes()
	assert.NoError(err, "ToBytes should not have errored")
	assert.Equal(b1, b2, "should be equal")
}

func TestCiphertextToBytes(t *testing.T) {
	assert := assert.New(t)

	c := Ciphertext{
		length:     4,
		ciphertext: []byte("hello"),
	}
	_, err := c.ToBytes()
	assert.Error(err, "ToBytes should not have errored")
	c = Ciphertext{
		length:     MessageCiphertextMaxSize,
		ciphertext: []byte("hello"),
	}
	_, err = c.ToBytes()
	assert.Error(err, "ToBytes should not have errored")
	c = Ciphertext{
		length:     MessageCiphertextMaxSize,
		ciphertext: make([]byte, MessageCiphertextMaxSize),
	}
	_, err = c.ToBytes()
	assert.NoError(err, "ToBytes should have errored")
}

func TestCiphertextFromBytes(t *testing.T) {
	assert := assert.New(t)

	c := Ciphertext{
		length:     5,
		ciphertext: []byte("hello"),
	}
	b, err := c.ToBytes()
	assert.NoError(err, "ToBytes should not have errored")
	binary.LittleEndian.PutUint16(b, 3)
	_, err = CiphertextFromBytes(b)
	assert.Error(err, "ToBytes should have errored")
}
