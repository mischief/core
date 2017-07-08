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

func TestToBytesFromBytes(t *testing.T) {
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
	message2, err := FromBytes(raw1)
	assert.NoError(err, "FromBytes failed")
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

func TestFromBytesIncorrectLength(t *testing.T) {
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
	_, err = FromBytes(raw1)
	assert.Error(err, "FromBytes should have failed")
}

func TestFromBytesIncorrectReserved(t *testing.T) {
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
	message2, err := FromBytes(raw1)
	assert.Error(err, "FromBytes should have failed")
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
