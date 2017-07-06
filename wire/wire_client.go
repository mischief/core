// Copyright 2017 David Anthony Stainton and Yawning Angel All rights reserved.
//
// Use of this source code is governed by a AGPL license
// that can be found in the LICENSE file in the root of the source
// tree.

package wire

import (
	"errors"
	"io"
	"net"
	"time"
)

const (
	// Maximum payload size permitted by wire protocol
	MAX_PAYLOAD_SIZE   = 65515
	SPHINX_PACKET_SIZE = 32768 // XXX: Yawning fix me
	ED25519_KEY_SIZE   = 32
	PROLOGUE_SIZE      = 1
)

// Options is used to configure various properties of the Katzen wire protocol
// client connection pool. Default values are used when a nil Options pointer
// is passed to NewKatzenWireClientPool.
// XXX TODO: add timeouts for sending
type Options struct {
	maxRetries int
	retryDelay time.Duration
}

var defaultOptions = Options{
	maxRetries: 3,
	retryDelay: 1 * time.Minute,
}

// Config is used to specify non-optional configuration for the
// Katzen client wire protocol connection pool.
type Config struct {
	// XXX todo: store my ed25519 keys and keys of my peers
}

// KatzenWireClientPool is the struct that keeps state for the wire protocol
// client pool connections which avoids redundant connections
type KatzenWireClientPool struct {
	options        *Options
	connMap        map[string]net.Conn
	sendChanMap    map[string]chan<- []byte
	receiveChanMap map[string]<-chan []byte
}

// NewKatzenWireClientPool creates a new client connection pool which uses
// the Katzen wire protocol.
func NewKatzenWireClientPool(options *Options, config *Config) *KatzenWireClientPool {
	wire := KatzenWireClientPool{}
	if options == nil {
		wire.options = &defaultOptions
	} else {
		wire.options = options
	}
	return &wire
}

func (p *KatzenWireClientPool) StopConn(network, addr string) {
	// XXX todo: fix me
}

func (p *KatzenWireClientPool) retryDial(network, addr string) error {
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

func (p *KatzenWireClientPool) sendLoop(sendChan chan []byte, writer io.Writer, network, addr string) {
	for {
		payload := <-sendChan
		_, err := writer.Write(payload[:])
		if err != nil {
			p.StopConn(network, addr)
		}
	}
}

func (p *KatzenWireClientPool) receiveLoop(receiveChan chan []byte, reader io.Reader, network, addr string) {
	for {
		payload := make([]byte, MAX_PAYLOAD_SIZE)
		_, err := io.ReadFull(reader, payload)
		if err != nil {
			p.StopConn(network, addr)
		}
		receiveChan <- payload
	}
}

// dial is used to dial a new connection to the remote host
func (p *KatzenWireClientPool) dial(network, addr string) error {
	conn, err := net.Dial(network, addr) // use DialTimeout instead?
	if err != nil {
		return err
	}

	// XXX TODO: send handshake to server

	// receive handshake from server
	/*
		serverHandshake := make([]byte, ED25519_KEY_SIZE+PROLOGUE_SIZE)
		_, err = io.ReadFull(conn, clientHandshake)
		if err != nil {
			return err
		}
	*/
	// XXX: todo: authenticate

	sendChan := make(chan []byte)
	receiveChan := make(chan []byte)
	go p.sendLoop(sendChan, conn, network, addr)
	go p.receiveLoop(receiveChan, conn, network, addr)
	p.sendChanMap[network+addr] = sendChan
	p.receiveChanMap[network+addr] = receiveChan
	p.connMap[network+addr] = conn

	return nil
}

// Send sends a payload to the given destination specified by
// network and addr utilizing a retry Dial.
func (p *KatzenWireClientPool) Send(network, addr string, payload [MAX_PAYLOAD_SIZE]byte) error {
	ch, ok := p.sendChanMap[network+addr]
	if !ok {
		err := p.retryDial(network, addr)
		if err != nil {
			return err
		}
	}
	ch <- payload[:]
	return nil
}
