// block_test.go - Noise based wire protocol client tests.
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

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBlockToBytesFromBytes(t *testing.T) {
	assert := assert.New(t)

	block1 := Block{}
	copy(block1.messageId[:], []byte(string("message id")))
	block1.totalBlocks = uint16(3)
	block1.blockId = uint16(96)
	copy(block1.block, []byte(string("zomg bbq wtf lol")))
	raw1 := block1.toBytes()
	block2 := FromBytes(raw1)
	raw2 := block2.toBytes()

	assert.Equal(raw1, raw2, "byte slices should be equal")
}
