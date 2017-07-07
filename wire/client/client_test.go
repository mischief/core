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

	// server noise config
	noiseConfig := noise.Config{}
	noiseConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	noiseConfig.Random = config.Random
	noiseConfig.Pattern = noise.HandshakeNN
	noiseConfig.Initiator = false
	noiseConfig.Prologue = []byte{session.options.PrologueVersion}
	noiseConfig.StaticKeypair = config.StaticKeypair
	noiseConfig.EphemeralKeypair = noise.DH25519.GenerateKeypair(config.Random)
	hs := noise.NewHandshakeState(noiseConfig)

	go func() {
		fmt.Println("server start")
		msg := make([]byte, 33)
		_, err := io.ReadFull(serverConn, msg)
		if err != nil {
			panic(err)
		}
		fmt.Printf("server received handshake len %d\n", len(msg))
		if msg[0] != byte(0) {
			panic("wtf version mismatch")
		}
		_, _, _, err = hs.ReadMessage(nil, msg[1:])
		fmt.Println("after server ReadMessage #1")
		handshakeMessage, _, _ := hs.WriteMessage(nil, nil)
		fmt.Printf("len of server response handshake message %d\n", len(handshakeMessage))
		prologue := byte(0)
		newMsg := make([]byte, 1)
		newMsg[0] = prologue
		newMsg = append(newMsg, handshakeMessage...)
		fmt.Printf("prepared server handshake response len %d\n", len(newMsg))
		count, err := serverConn.Write(msg)
		if err != nil {
			panic(err)
		}
		if count != len(msg) {
			panic("count unequal")
		}
		fmt.Println("server sent handshake response")
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
