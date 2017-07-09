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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommandNoOp(t *testing.T) {
	assert := assert.New(t)
	var err error
	var cmd1, cmd2 Command
	cmd1 = new(NoOpCommand)
	raw1 := cmd1.toBytes()
	cmd2, err = fromBytes(raw1)
	assert.NoError(err, "fromBytes unexpectedly failed")
	raw2 := cmd2.toBytes()
	assert.Equal(raw1, raw2, "serialized commands not equal")
}

func TestCommandDisconnect(t *testing.T) {
	assert := assert.New(t)
	var err error
	var cmd1, cmd2 Command
	cmd1 = new(DisconnectCommand)
	raw1 := cmd1.toBytes()
	cmd2, err = fromBytes(raw1)
	assert.NoError(err, "fromBytes unexpectedly failed")
	raw2 := cmd2.toBytes()
	assert.Equal(raw1, raw2, "serialized commands not equal")
}

func TestCommandAuthenticate(t *testing.T) {
	assert := assert.New(t)
	var err error
	var cmd1, cmd2 Command
	cmd1 = new(AuthenticateCommand)
	raw1 := cmd1.toBytes()
	cmd2, err = fromBytes(raw1)
	assert.NoError(err, "fromBytes unexpectedly failed")
	raw2 := cmd2.toBytes()
	assert.Equal(raw1, raw2, "serialized commands not equal")
}

func TestCommandSendPacket(t *testing.T) {
	assert := assert.New(t)
	var err error
	var cmd1, cmd2 Command
	cmd1 = new(SendPacketCommand)
	raw1 := cmd1.toBytes()
	cmd2, err = fromBytes(raw1)
	assert.NoError(err, "fromBytes unexpectedly failed")
	raw2 := cmd2.toBytes()
	assert.Equal(raw1, raw2, "serialized commands not equal")
}
