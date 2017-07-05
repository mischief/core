// Copyright 2017 David Anthony Stainton and Yawning Angel All rights reserved.
//
// Use of this source code is governed by a AGPL license
// that can be found in the LICENSE file in the root of the source
// tree.

package wire

import (
	"io"
	"net"
	"sync"
	//
	//	"github.com/flynn/noise"
)

// KatzenWireServer is the server wire protocol struct
// for Katzenpost link layer.
type KatzenWireServer struct {
	network string
	address string

	conns     []net.Conn
	listener  net.Listener
	waitGroup *sync.WaitGroup
	stopping  bool
}

// NewKatzenWireServer creates a new KatzenWireServer given
// network and address strings
func NewKatzenWireServer(network, address string) *KatzenWireServer {
	wire := KatzenWireServer{
		network: network,
		address: address,
	}
	return &wire
}

// Start the KatzenWireServer
func (w *KatzenWireServer) Start() error {
	var err error
	w.listener, err = net.Listen(w.network, w.address)
	if err != nil {
		return err
	}
	w.waitGroup.Add(1)
	go w.acceptLoop()
	return nil
}

// Stop will kill our listener and all it's connections
func (w *KatzenWireServer) Stop() {
	w.stopping = true
	if w.listener != nil {
		w.listener.Close()
	}
	w.waitGroup.Wait()
}

// acceptLoop is called by our Start method
func (w *KatzenWireServer) acceptLoop() {
	defer w.waitGroup.Done()
	defer func() {
		for _, conn := range w.conns {
			if conn != nil {
				conn.Close()
			}
		}
	}()
	defer w.listener.Close()

	for {
		conn, err := w.listener.Accept()
		if err != nil {
			if w.stopping {
				return
			} else {
				continue
			}
		}

		w.conns = append(w.conns, conn)
		go w.handleConnection(conn, len(w.conns)-1)
	}
}

// handleConnection is called implicitly by our Start method via our
// acceptLoop method
func (w *KatzenWireServer) handleConnection(conn net.Conn, id int) error {
	defer func() {
		conn.Close()
		w.conns[id] = nil
	}()

	if err := w.receiveHandshake(conn); err != nil {
		return err
	}
	return nil
}

// receiveHandshake receives a handshake from our client.
// This is the beginning of our wire protocol state machine
// where the noise handshake is received and responded to.
func (w *KatzenWireServer) receiveHandshake(conn io.ReadWriter) error {

	// XXX todo: write me
	return nil
}

type KatzenWireClient struct {
}

func NewKatzenWireClient() *KatzenWireClient {
	wire := KatzenWireClient{}
	return &wire
}
