// client_test.go - Noise based wire protocol server tests.
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
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Katzenpost/core/wire/common"
	"github.com/flynn/noise"
)

func TestClientStopConnEmpty(t *testing.T) {
	config := Config{
		StaticKeypair: noise.DH25519.GenerateKeypair(rand.Reader),
		Random:        rand.Reader,
	}
	client := New(nil, &config)
	client.StopConn("tcp", "127.0.0.1:6669")
}

func TestClientSendFail(t *testing.T) {
	options := Options{
		MaxRetries:        2,
		RetryDelay:        0,
		ReadWriteDeadline: time.Time{},
	}
	config := Config{
		StaticKeypair: noise.DH25519.GenerateKeypair(rand.Reader),
		Random:        rand.Reader,
	}
	client := New(&options, &config)
	emptyPayload := [common.MaxPayloadSize]byte{}

	serverConn, _ := net.Pipe()
	go func() {
		if _, err := io.Copy(serverConn, serverConn); err != nil {
			fmt.Println(err.Error())
		}
	}()
	err := client.Send("tcp", "127.0.0.1:6669", emptyPayload)
	fmt.Println(err)
}
