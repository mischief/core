// commands_test.go - Tests for wire protocol commands.
// Copyright (C) 2017  David Anthony Stainton, Yawning Angel
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

package commands

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/core/constants"
	sphinxConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/require"
)

func TestNoOp(t *testing.T) {
	require := require.New(t)

	cmd := &NoOp{}
	b := cmd.ToBytes()
	require.Equal(cmdOverhead, len(b), "NoOp: ToBytes() length")

	c, err := FromBytes(b)
	require.NoError(err, "NoOp: FromBytes() failed")
	require.IsType(cmd, c, "NoOp: FromBytes() invalid type")
}

func TestDisconnect(t *testing.T) {
	require := require.New(t)

	cmd := &Disconnect{}
	b := cmd.ToBytes()
	require.Equal(cmdOverhead, len(b), "Disconnect: ToBytes() length")

	c, err := FromBytes(b)
	require.NoError(err, "Disconnect: FromBytes() failed")
	require.IsType(cmd, c, "Disconnect: FromBytes() invalid type")
}

func TestSendPacket(t *testing.T) {
	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

	require := require.New(t)

	cmd := &SendPacket{SphinxPacket: []byte(payload)}
	b := cmd.ToBytes()
	require.Equal(cmdOverhead+len(payload), len(b), "SendPacket: ToBytes() length")

	c, err := FromBytes(b)
	require.NoError(err, "SendPacket: FromBytes() failed")
	require.IsType(cmd, c, "SendPacket: FromBytes() invalid type")

	cmd = c.(*SendPacket)
	require.Equal([]byte(payload), cmd.SphinxPacket, "SendPacket: FromBytes() SphinxPacket")
}

func TestRetrieveMessage(t *testing.T) {
	const seq = 0xbeefbeef

	require := require.New(t)

	cmd := &RetrieveMessage{Sequence: seq}
	b := cmd.ToBytes()
	require.Equal(cmdOverhead+4, len(b), "RetrieveMessage: ToBytes() length")

	c, err := FromBytes(b)
	require.NoError(err, "RetrieveMessage: FromBytes() failed")
	require.IsType(cmd, c, "RetrieveMessage: FromBytes() invalid type")

	cmd = c.(*RetrieveMessage)
	require.Equal(uint32(seq), cmd.Sequence, "RetrieveMessage: FromBytes() Sequence")
}

func TestMessage(t *testing.T) {
	const (
		// All packet lenghts are currently normalized.
		expectedLen = cmdOverhead + messageEmptyLength
		hint        = 0x17
		seq         = 0xa5a5a5a5
	)

	require := require.New(t)

	// Generate the payload.
	payload := make([]byte, constants.ForwardPayloadLength)
	_, err := rand.Read(payload)
	require.NoError(err, "Message: failed to generate payload")

	// MessageEmpty
	cmdEmpty := &MessageEmpty{Sequence: seq}
	b := cmdEmpty.ToBytes()
	require.Equal(expectedLen, len(b), "MessageEmpty: ToBytes() length")

	c, err := FromBytes(b)
	require.NoError(err, "MessageEmpty: FromBytes() failed")
	require.IsType(cmdEmpty, c, "MessageEmpty: FromBytes() invalid type")

	cmdEmpty = c.(*MessageEmpty)
	require.Equal(uint32(seq), cmdEmpty.Sequence, "MessageEmpty: FromBytes() Sequence")

	// Message
	msgPayload := payload[:constants.UserForwardPayloadLength]
	cmdMessage := &Message{
		QueueSizeHint: hint,
		Sequence:      seq,
		Payload:       msgPayload,
	}
	b = cmdMessage.ToBytes()
	require.Equal(expectedLen, len(b), "Message: ToBytes() length")

	c, err = FromBytes(b)
	require.NoError(err, "Message: FromBytes() failed")
	require.IsType(cmdMessage, c, "Message: FromBytes() invalid type")

	cmdMessage = c.(*Message)
	require.Equal(uint8(hint), cmdMessage.QueueSizeHint, "Message: FromBytes() QueueSizeHint")
	require.Equal(uint32(seq), cmdMessage.Sequence, "Message: FromBytes() Sequence")
	require.Equal(msgPayload, cmdMessage.Payload, "Message: FromBytes() Payload")

	// MessageACK
	id := make([]byte, sphinxConstants.SURBIDLength)
	_, err = rand.Read(id[:])
	require.NoError(err, "MessageACK: Failed to generate ID")

	cmdMessageACK := &MessageACK{
		QueueSizeHint: hint,
		Sequence:      seq,
		Payload:       payload,
	}
	copy(cmdMessageACK.ID[:], id[:])
	b = cmdMessageACK.ToBytes()
	require.Equal(expectedLen, len(b), "MessageACK: ToBytes() length")

	c, err = FromBytes(b)
	require.NoError(err, "MessageACK: FromBytes() failed")
	require.IsType(cmdMessageACK, c, "MessageACK: FromBytes() invalid type")

	cmdMessageACK = c.(*MessageACK)
	require.Equal(uint8(hint), cmdMessageACK.QueueSizeHint, "MessageACK: FromBytes() QueueSizeHint")
	require.Equal(uint32(seq), cmdMessageACK.Sequence, "MessageACK: FromBytes() Sequence")
	require.Equal(id[:], cmdMessageACK.ID[:], "MessageACK: FromBytes() ID")
	require.Equal(payload, cmdMessageACK.Payload, "MessageACK: FromBytes() Payload")
}
