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
	"net"
	"time"

	"github.com/Katzenpost/core/wire/common"
	"github.com/flynn/noise"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("client")

// Options is used to configure various properties of the wire protocol
// client connection pool. Default values are used when a nil Options pointer
// is passed to NewWireClientPool.
type Options struct {
	MaxRetries        int
	RetryDelay        time.Duration
	ReadWriteDeadline time.Time
}

var defaultOptions = Options{
	MaxRetries:        3,
	RetryDelay:        1 * time.Minute,
	ReadWriteDeadline: time.Time{},
}

// Config is used to specify non-optional configuration for the
// client wire protocol connection pool.
type Config struct {
	// XXX todo: store my ed25519 keys and keys of my peers?
	StaticKeypair noise.DHKey
	Random        io.Reader
}

// Client is the struct that keeps state for the wire protocol
// client pool connections which avoids redundant connections
type Client struct {
	options       *Options
	sessionMap    map[string]common.Session
	staticKeypair noise.DHKey
	random        io.Reader
}

// New creates a new client connection pool which uses
// the wire protocol.
func New(options *Options, config *Config) *Client {
	client := Client{
		sessionMap: make(map[string]common.Session),
	}
	if options == nil {
		client.options = &defaultOptions
	} else {
		client.options = options
	}
	client.staticKeypair = config.StaticKeypair
	return &client
}

// StopConn is used to stop a particular connection
func (c *Client) StopConn(network, addr string) {
	log.Debugf("stopping connection to %s:%s", network, addr)
	session, ok := c.sessionMap[network+addr]
	if ok {
		err := session.Close()
		if err != nil {
			log.Debugf("failed to close: %s", err)
		}
		delete(c.sessionMap, network+addr)
	}
}

func (c *Client) retryDial(network, addr string) (common.Session, error) {
	var err error
	var session common.Session
	attempt := 1
	for {
		log.Debugf("dialing attempt %d to %s:%s", attempt, network, addr)
		session, err = c.dial(network, addr)
		if err == nil {
			break
		}
		if attempt >= c.options.MaxRetries {
			return nil, fmt.Errorf("reached connection retry limit for destination %s:%s. Failed with: %s", network, addr, err)
		}
		time.Sleep(c.options.RetryDelay)
		attempt++
	}
	return session, err
}

// dial is used to dial a new connection to the remote host
func (c *Client) dial(network, addr string) (common.Session, error) {
	conn, err := net.Dial(network, addr) // use DialTimeout instead?
	if err != nil {
		return nil, err
	}
	err = conn.SetDeadline(c.options.ReadWriteDeadline)
	if err != nil {
		log.Debugf("failed to set deadline: %s", err)
	}
	sessionConfig := SessionConfig{
		StaticKeypair: c.staticKeypair,
	}
	sessionOptions := SessionOptions{}
	session := NewSession(&sessionConfig, c.random, &sessionOptions)
	err = session.Initiate(conn)
	if err != nil {
		log.Errorf("failed to initiate session to %s:%s", network, addr)
		return nil, err
	}
	c.sessionMap[network+addr] = session
	return session, nil
}

// Send sends a payload to the given destination specified by
// network and addr utilizing a retry Dial.
func (c *Client) Send(network, addr string, payload [common.MaxPayloadSize]byte) error {
	var err error
	session, ok := c.sessionMap[network+addr]
	if !ok {
		session, err = c.retryDial(network, addr)
		if err != nil {
			log.Error(err)
			return err
		}
	}
	err = session.Send(payload[:])
	if err != nil {
		log.Errorf("failed to send payload to %s:%s", network, addr)
	}
	return err
}

// SessionOptions is used to configure various properties of the client session
type SessionOptions struct {
	prologueVersion byte
}

var defaultSessionOptions = SessionOptions{
	prologueVersion: byte(0),
}

// SessionConfig is non-optional configuration for a Session
type SessionConfig struct {
	StaticKeypair noise.DHKey
}

// Session handles the client side of our
// Noise based wire protocol as specified in the
// Panoramix Mix Network Wire Protocol Specification
type Session struct {
	options             *SessionOptions
	noiseConfig         noise.Config
	noiseHandshakeState *noise.HandshakeState
}

// NewSession creates a new session.
func NewSession(config *SessionConfig, random io.Reader, options *SessionOptions) Session {
	session := Session{}
	if options == nil {
		session.options = &defaultSessionOptions
	} else {
		session.options = options
	}
	session.noiseConfig = noise.Config{}
	session.noiseConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	session.noiseConfig.Random = random
	session.noiseConfig.Pattern = noise.HandshakeNN
	session.noiseConfig.Initiator = true
	session.noiseConfig.Prologue = []byte{session.options.prologueVersion}
	session.noiseConfig.StaticKeypair = config.StaticKeypair
	session.noiseConfig.EphemeralKeypair = noise.DH25519.GenerateKeypair(random)
	return session
}

// Initiate starts our protocol state machine
// and returns when the session is finished.
func (s Session) Initiate(conn io.ReadWriter) error {
	// XXX todo: send handshake et cetera
	return nil
}

// Send sends a payload using the Session
func (s Session) Send(payload []byte) error {
	// XXX fix me
	return nil
}

// Close closes the Session
func (s Session) Close() error {
	// XXX fix me
	return nil
}
