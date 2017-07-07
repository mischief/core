// client_test.go - Noise based wire protocol client tests.
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
	"github.com/stretchr/testify/assert"
)

func TestClientHandshake(t *testing.T) {
	assert := assert.New(t)
	config := Config{
		StaticKeypair: noise.DH25519.GenerateKeypair(rand.Reader),
		Random:        rand.Reader,
	}
	session := New(&config, nil)
	clientConn, serverConn := net.Pipe()

	serverStaticKeypair := noise.DH25519.GenerateKeypair(rand.Reader)
	serverConfig := noise.Config{}
	serverConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	serverConfig.Random = rand.Reader
	serverConfig.Pattern = noise.HandshakeNN
	serverConfig.Initiator = false
	serverConfig.Prologue = []byte{0}
	serverConfig.StaticKeypair = serverStaticKeypair
	serverConfig.EphemeralKeypair = noise.DH25519.GenerateKeypair(rand.Reader)
	serverHs := noise.NewHandshakeState(serverConfig)

	go func() {
		fmt.Println("server start")

		// server reads client's initial handshake message
		clientHsMsg := make([]byte, 33)
		_, err := io.ReadFull(serverConn, clientHsMsg)
		assert.NoError(err, "server failed to receive client handshake message")
		assert.Equal(33, len(clientHsMsg), "server received unexpected length client handshake message")

		serverHsResult, _, _, err := serverHs.ReadMessage(nil, clientHsMsg[1:])
		assert.NoError(err, "server failed to 'ReadMessage' client handshake message")
		assert.Equal(0, len(serverHsResult), "server result message is unexpected size")

		serverHsMsg := make([]byte, 1)
		hsMsg, csR0, csR1 := serverHs.WriteMessage(nil, nil)
		serverHsMsg = append(serverHsMsg, hsMsg...)

		count, err := serverConn.Write(serverHsMsg)
		assert.NoError(err, "server failed to send handshake response message")
		assert.Equal(count, len(serverHsMsg), "server sent incorrect length handshake message")

		fmt.Println("server sent handshake response")

		authMsg := csR1.Encrypt(nil, nil, []byte("AUTHENTICATE"))
		count, err = serverConn.Write(authMsg)
		assert.NoError(err, "server failed to send auth message")
		assert.Equal(count, len(authMsg), "server sent incorrect length auth message")

		expected := []byte("AUTH ME")
		clientAuthMsg := make([]byte, len(expected))
		_, err = io.ReadFull(serverConn, clientAuthMsg)
		assert.NoError(err, "server failed to receive client auth message")

		res, err := csR0.Decrypt(nil, nil, clientAuthMsg)
		assert.NoError(err, "server failed to decrypt client auth message")
		assert.Equal([]byte("AUTH ME"), res, "server received unexpected message")
	}()

	err := session.Initiate(clientConn)
	assert.NoError(err, "client failed to Initiate")
	fmt.Println("after Initiate")

	// don't call Send here because the server isn't listening anymore
	// therefore our Send will block forever
	//
	//packet := []byte{0, 1, 2, 3}
	//err = session.Send(packet)
	//assert.NoError(err, "client failed to Send")
	//fmt.Println("after Send")

	err = session.Close()
	assert.NoError(err, "client failed to Close")
	fmt.Println("after Close")
}
