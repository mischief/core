// noise_test.go - Test for noise parameters.
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
	"testing"

	"github.com/Katzenpost/noise"
	"github.com/stretchr/testify/assert"
)

func TestNoiseParams(t *testing.T) {
	assert := assert.New(t)

	clientStaticKeypair := noise.DH25519.GenerateKeypair(rand.Reader)
	clientConfig := noise.Config{}
	clientConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	clientConfig.Random = rand.Reader
	clientConfig.Pattern = noise.HandshakeNN
	clientConfig.Initiator = true
	clientConfig.Prologue = []byte{0}
	clientConfig.StaticKeypair = clientStaticKeypair
	clientConfig.EphemeralKeypair = noise.DH25519.GenerateKeypair(rand.Reader)
	clientHs := noise.NewHandshakeState(clientConfig)

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

	clientHsMsg, _, _ := clientHs.WriteMessage(nil, nil)
	assert.Equal(32, len(clientHsMsg), "client handshake message is unexpected size")

	serverHsResult, _, _, err := serverHs.ReadMessage(nil, clientHsMsg)
	assert.NoError(err, "server failed to read client handshake message")
	assert.Equal(0, len(serverHsResult), "server result message is unexpected size")

	serverHsMsg, csR0, csR1 := serverHs.WriteMessage(nil, nil)
	assert.Equal(48, len(serverHsMsg), "server handshake message is unexpected size")

	clientHsResult, csI0, csI1, err := clientHs.ReadMessage(nil, serverHsMsg)
	assert.NoError(err, "client failed to read server handshake message")
	assert.Equal(0, len(clientHsResult), "client result message is unexpected size")

	clientMessage := []byte("hello")
	msg := csI0.Encrypt(nil, nil, clientMessage)
	res, err := csR0.Decrypt(nil, nil, msg)
	assert.Equal(clientMessage, res, "server received unexpected message")

	serverMessage := []byte("bye")
	msg = csR1.Encrypt(nil, nil, serverMessage)
	res, err = csI1.Decrypt(nil, nil, msg)
	assert.Equal(serverMessage, res, "client received unexpected message")

	serverMessage = []byte("bye bye")
	msg = csR1.Encrypt(nil, nil, serverMessage)
	res, err = csI1.Decrypt(nil, nil, msg)
	assert.Equal(serverMessage, res, "client received unexpected message")

	clientMessage = []byte("hello again")
	msg = csI0.Encrypt(nil, nil, clientMessage)
	res, err = csR0.Decrypt(nil, nil, msg)
	assert.Equal(clientMessage, res, "server received unexpected message")

	serverMessage = []byte("bye again")
	msg = csR1.Encrypt(nil, nil, serverMessage)
	res, err = csI1.Decrypt(nil, nil, msg)
	assert.Equal(serverMessage, res, "client received unexpected message")
}
