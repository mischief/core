// Copyright 2017 David Anthony Stainton and Yawning Angel All rights reserved.
//
// Use of this source code is governed by a AGPL license
// that can be found in the LICENSE file in the root of the source
// tree.

package client

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/Katzenpost/core/wire/common"
	"github.com/flynn/noise"
)

// Options is used to configure various properties of the wire protocol
// client connection pool. Default values are used when a nil Options pointer
// is passed to NewWireClientPool.
// XXX TODO: add timeouts for sending/receiving
type Options struct {
	maxRetries      int
	retryDelay      time.Duration
	prologueVersion byte
}

var defaultOptions = Options{
	maxRetries:      3,
	retryDelay:      1 * time.Minute,
	prologueVersion: byte(0),
}

// Config is used to specify non-optional configuration for the
// client wire protocol connection pool.
type Config struct {
	// XXX todo: store my ed25519 keys and keys of my peers
	StaticKeypair noise.DHKey
}

// Client is the struct that keeps state for the wire protocol
// client pool connections which avoids redundant connections
type Client struct {
	options      *Options
	noiseConfig  noise.Config
	connMap      map[string]net.Conn
	sendChMap    map[string]chan<- []byte
	receiveChMap map[string]<-chan []byte
	stateMap     map[string]*noise.HandshakeState
}

// New creates a new client connection pool which uses
// the wire protocol.
func New(options *Options, config *Config, random io.Reader) *Client {
	wire := Client{}
	if options == nil {
		wire.options = &defaultOptions
	} else {
		wire.options = options
	}
	wire.noiseConfig = noise.Config{}
	wire.noiseConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	wire.noiseConfig.Random = random
	wire.noiseConfig.Pattern = noise.HandshakeNN
	wire.noiseConfig.Initiator = true
	wire.noiseConfig.Prologue = []byte{wire.options.prologueVersion}
	wire.noiseConfig.StaticKeypair = config.StaticKeypair
	wire.noiseConfig.EphemeralKeypair = noise.DH25519.GenerateKeypair(random)
	return &wire
}

// StopConn is used to stop a particular connection
func (p *Client) StopConn(network, addr string) {
	delete(p.connMap, network+addr)
	delete(p.sendChMap, network+addr)
	delete(p.receiveChMap, network+addr)
}

func (p *Client) retryDial(network, addr string) error {
	var err error
	attempt := 1
	for {
		err = p.dial(network, addr)
		if err == nil {
			break
		}
		// XXX print log message containing dial error?
		if attempt > p.options.maxRetries {
			return errors.New("exceeded connection retry limit")
		}
		time.Sleep(p.options.retryDelay)
		attempt++
	}
	return err
}

func (p *Client) sendLoop(sendCh chan []byte, w io.Writer, network, addr string) {
	for {
		payload := <-sendCh
		_, err := w.Write(payload[:])
		if err != nil {
			p.StopConn(network, addr)
		}
	}
}

func (p *Client) receiveLoop(receiveCh chan []byte, r io.Reader, network, addr string) {
	for {
		_, ok := p.connMap[network+addr]
		if !ok {
			break
		}
		payload := make([]byte, common.MaxPayloadSize)
		_, err := io.ReadFull(r, payload)
		if err != nil {
			p.StopConn(network, addr)
		}
		receiveCh <- payload
	}
}

// dial is used to dial a new connection to the remote host
func (p *Client) dial(network, addr string) error {
	conn, err := net.Dial(network, addr) // use DialTimeout instead?
	if err != nil {
		return err
	}

	// XXX TODO: send handshake to server
	//noiseHandshakeState := noise.NewHandshakeState(p.noiseConfig)

	// receive handshake from server
	/*
		serverHandshake := make([]byte, ED25519_KEY_SIZE+PROLOGUE_SIZE)
		_, err = io.ReadFull(conn, clientHandshake)
		if err != nil {
			return err
		}
	*/
	// XXX: todo: authenticate

	sendCh := make(chan []byte)
	receiveCh := make(chan []byte)
	go p.sendLoop(sendCh, conn, network, addr)
	go p.receiveLoop(receiveCh, conn, network, addr)
	p.sendChMap[network+addr] = sendCh
	p.receiveChMap[network+addr] = receiveCh
	p.connMap[network+addr] = conn

	return nil
}

// Send sends a payload to the given destination specified by
// network and addr utilizing a retry Dial.
func (p *Client) Send(network, addr string, payload [common.MaxPayloadSize]byte) error {
	ch, ok := p.sendChMap[network+addr]
	if !ok {
		err := p.retryDial(network, addr)
		if err != nil {
			return err
		}
	}
	ch <- payload[:]
	return nil
}
