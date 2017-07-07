// client.go - Noise based wire protocol.
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

// Package client provides the Katzenpost noise based client side wire protocol.
package client

import (
	"fmt"
	"io"

	"github.com/Katzenpost/core/wire/common"
	"github.com/flynn/noise"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("client")

// SessionOptions is used to configure various properties of the client session
type Options struct {
	PrologueVersion byte
}

var defaultSessionOptions = Options{
	PrologueVersion: byte(0),
}

// SessionConfig is non-optional configuration for a Session
type Config struct {
	StaticKeypair noise.DHKey
	Random        io.Reader
}

// Session handles the client side of our
// Noise based wire protocol as specified in the
// Panoramix Mix Network Wire Protocol Specification
type Session struct {
	options      *Options
	conn         io.ReadWriteCloser
	noiseConfig  noise.Config
	hsState      *noise.HandshakeState // hsState is the Noise handshake state
	cipherState0 *noise.CipherState
	cipherState1 *noise.CipherState
}

// New creates a new session.
func New(config *Config, options *Options) *Session {
	session := Session{}
	if options == nil {
		session.options = &defaultSessionOptions
	} else {
		session.options = options
	}
	session.noiseConfig = noise.Config{}
	session.noiseConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	session.noiseConfig.Random = config.Random
	session.noiseConfig.Pattern = noise.HandshakeNN
	session.noiseConfig.Initiator = true
	session.noiseConfig.Prologue = []byte{session.options.PrologueVersion}
	session.noiseConfig.StaticKeypair = config.StaticKeypair
	session.noiseConfig.EphemeralKeypair = noise.DH25519.GenerateKeypair(config.Random)
	session.hsState = noise.NewHandshakeState(session.noiseConfig)
	return &session
}

// Initiate starts our client session state machine
func (s *Session) Initiate(conn io.ReadWriteCloser) error {
	s.conn = conn
	err := s.handshake()
	if err != nil {
		panic(err)
	}
	err = s.authenticate()
	if err != nil {
		panic(err)
	}
	return nil
}

// Handshake performs the noise based handshake exchange
// with the server
func (s *Session) handshake() error {
	log.Debug("client initiates handshake")

	clientHsMsg := make([]byte, 1)
	hsMsg := make([]byte, 32)
	hsMsg, _, _ = s.hsState.WriteMessage(nil, nil)

	clientHsMsg[0] = s.options.PrologueVersion
	clientHsMsg = append(clientHsMsg, hsMsg...)

	count, err := s.conn.Write(clientHsMsg)
	if err != nil {
		return err
	}
	if count != len(clientHsMsg) {
		return fmt.Errorf("client did not send correct handshake length bytes: %d != %d", count, len(clientHsMsg))
	}
	log.Debug("client sent handshake message")

	receivedHsMsg := make([]byte, 49)
	_, err = io.ReadFull(s.conn, receivedHsMsg)
	if err != nil {
		return err
	}
	log.Debug("client received server handshake message")

	// decode hs message from server
	clientHsResult := make([]byte, 0)
	clientHsResult, s.cipherState0, s.cipherState1, err = s.hsState.ReadMessage(nil, receivedHsMsg[1:])
	if err != nil {
		return err
	}
	if len(clientHsResult) != 0 {
		return fmt.Errorf("client decoded incorrect message length: %d != %d", len(clientHsResult), 0)
	}
	return nil
}

func (s *Session) authenticate() error {
	// XXX todo, stuff goes here
	return nil
}

// Receive receives a payload
func (s *Session) Receive(payload [common.MaxPayloadSize]byte) error {
	log.Debug("client Receive")
	ciphertext := [common.MaxPayloadSize]byte{}
	_, err := io.ReadFull(s.conn, ciphertext[:])
	if err != nil {
		return err
	}
	plaintext, err := s.cipherState1.Decrypt(nil, nil, ciphertext[:])
	if err != nil {
		return err
	}
	// XXX copy is slow. do something different?
	copy(payload[:], plaintext)
	return nil
}

// Send sends a payload
func (s *Session) Send(payload [common.MaxPayloadSize]byte) error {
	log.Debug("client Send")

	ciphertext := s.cipherState0.Encrypt(nil, nil, payload[:])
	count, err := s.conn.Write(ciphertext)
	if err != nil {
		return err
	}
	if count != len(ciphertext) {
		return fmt.Errorf("Client Session Send failed to write entire buffer: %d != %d", count, len(ciphertext))
	}
	return nil
}

// Close closes the Session
func (s *Session) Close() error {
	return s.conn.Close()
}
