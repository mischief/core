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

	"github.com/flynn/noise"
)

func TestSession(t *testing.T) {
	config := Config{
		StaticKeypair: noise.DH25519.GenerateKeypair(rand.Reader),
		Random:        rand.Reader,
	}
	session := New(&config, nil)
	clientConn, serverConn := net.Pipe()
	go func() {
		if _, err := io.Copy(serverConn, serverConn); err != nil {
			fmt.Println(err.Error())
		}
	}()
	err := session.Initiate(clientConn)
	if err != nil {
		panic(err)
	}
	packet := []byte{0, 1, 2, 3}
	err = session.Send(packet)
	if err != nil {
		panic(err)
	}
	err = session.Close()
	if err != nil {
		panic(err)
	}
}
