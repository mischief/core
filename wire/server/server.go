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
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("wire_server")

// Server is the server wire protocol struct
// for our link layer.
type Server struct {
	network string
	address string

	conns     []net.Conn
	listener  net.Listener
	waitGroup *sync.WaitGroup
	stopping  bool
}

// New creates a new Server given
// network and address strings
func New(network, address string) *Server {
	wire := Server{
		network: network,
		address: address,
	}
	return &wire
}

// Start the Server
func (w *Server) Start() error {
	var err error
	log.Debugf("starting server %s:%s", w.network, w.address)
	w.listener, err = net.Listen(w.network, w.address)
	if err != nil {
		return err
	}
	w.waitGroup.Add(1)
	go w.acceptLoop()
	return nil
}

// Stop will kill our listener and all it's connections
func (w *Server) Stop() {
	log.Debugf("stopping server %s:%s", w.network, w.address)
	w.stopping = true
	if w.listener != nil {
		err := w.listener.Close()
		if err != nil {
			log.Debugf("failed to close: %s", err)
		}
	}
	w.waitGroup.Wait()
}

// acceptLoop is called by our Start method
func (w *Server) acceptLoop() {
	defer w.waitGroup.Done()
	defer func() {
		log.Debugf("acceptLoop stopping for listener service %s:%s", w.network, w.address)
		for i, conn := range w.conns {
			if conn != nil {
				log.Debugf("Closing connection #%d", i)
				err := conn.Close()
				if err != nil {
					log.Debugf("failed to close: %s", err)
				}
			}
		}
	}()
	defer func() {
		err := w.listener.Close()
		if err != nil {
			log.Debugf("failed to close: %s", err)
		}
	}()

	for {
		conn, err := w.listener.Accept()
		if err != nil {
			log.Errorf("server connection accept failure: %s\n", err)
			if !w.stopping {
				continue
			}
			return
		}

		w.conns = append(w.conns, conn)
		go w.handleConnection(conn, len(w.conns)-1)
	}
}

// handleConnection is called implicitly by our Start method via our
// acceptLoop method
func (w *Server) handleConnection(conn net.Conn, id int) {
	defer func() {
		log.Debugf("Closing connection #%d", id)
		err := conn.Close()
		if err != nil {
			log.Debugf("failed to close: %s", err)
		}
		w.conns[id] = nil
	}()

	log.Debugf("Starting connection #%d", id)
	if err := w.receiveHandshake(conn); err != nil {
		log.Debugf(err.Error())
	}
}

// receiveHandshake receives a handshake from our client.
// This is the beginning of our wire protocol state machine
// where the noise handshake is received and responded to.
func (w *Server) receiveHandshake(conn io.ReadWriter) error {

	// XXX todo: write me
	return nil
}
