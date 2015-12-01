// Copyright (C) 2015 RayXXZhang
// All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license.  See the LICENSE file for details.

package tlslog

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
)

// TLSLog is a wrapper of tls. TlsLog can dial to the tls server
// and log client random and masterSecret to specific file
// which can be used to decrypt ssl application data
// in wireshark
type TLSLog struct {
	log     string
	logRand *logRand
	logFile string
}

func clientSessionCacheKey(conn *tls.Conn, config *tls.Config) string {
	if len(config.ServerName) > 0 {
		return config.ServerName
	}
	addr := conn.RemoteAddr().String()
	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]
	return hostname
}

// NewTLSLog returns a TLSLog with logFile set.
// logFile is the file path to store client random and masterSecret
// If logFile is empty, then the environment variable
// SSLKEYLOGFILE will be used instead
func NewTLSLog(logFile string) (*TLSLog, error) {
	tlsLog := TLSLog{
		logFile: logFile,
	}
	return &tlsLog, nil
}

// Conn is returned by Server/Client,
// it stores tls.Conn and tls.Config used
// in Handshark
type Conn struct {
	config *tls.Config
	conn   *tls.Conn
	tlsLog *TLSLog
}

// Server function is unimplemented
func (l *TLSLog) Server(conn net.Conn, config *tls.Config) *Conn {
	l.initConfig(config)
	return &Conn{
		config: config,
		conn:   tls.Server(conn, config),
		tlsLog: l,
	}
}

// Client use tls.Client to build a tls.Conn and return a TlsLog.Conn
// for Handshake
func (l *TLSLog) Client(conn net.Conn, config *tls.Config) *Conn {
	l.initConfig(config)
	return &Conn{
		config: config,
		conn:   tls.Client(conn, config),
		tlsLog: l,
	}
}

// Handshake uses tls.Conn.Handshake to perform server/client handshake
// and write masterSecret and client random to log file.
func (c *Conn) Handshake() (*tls.Conn, error) {
	err := c.conn.Handshake()

	if err != nil {
		return c.conn, err
	}
	err = c.tlsLog.writeLog(c.conn, c.config)

	return c.conn, err
}

type listener struct {
	listener net.Listener
	tlsLog   *TLSLog
	config   *tls.Config
}

func (l *listener) Accept() (c net.Conn, err error) {
	c, err = l.listener.Accept()
	if err != nil {
		return c, err
	}
	return c, l.tlsLog.writeLog(c.(*tls.Conn), l.config)

}
func (l *listener) Close() error {
	return l.listener.Close()
}

func (l *listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Listen function is unimplemented
func (l *TLSLog) Listen(network, laddr string, config *tls.Config) (net.Listener, error) {
	l.initConfig(config)
	originalListener, err := tls.Listen(network, laddr, config)
	newListener := &listener{
		listener: originalListener,
		tlsLog:   l,
		config:   config,
	}
	return newListener, err
}

// Dial uses tls.Dial to connect to tls server and write
// master secret and client to log file.
func (l *TLSLog) Dial(network, addr string, config *tls.Config) (*tls.Conn, error) {
	return l.DialWithDialer(new(net.Dialer), network, addr, config)
}

// DialWithDialer uses tls.DialWithDialer to connect to tls server and write
// master secret and client to log file.
func (l *TLSLog) DialWithDialer(dialer *net.Dialer, network, addr string, config *tls.Config) (*tls.Conn, error) {
	l.initConfig(config)

	conn, err := tls.DialWithDialer(dialer, network, addr, config)
	if err != nil {
		return conn, err
	}
	return conn, l.writeLog(conn, config)
}

func (l *TLSLog) initConfig(config *tls.Config) {
	l.log = ""
	l.logRand = newLogRand(config.Rand)
	config.Rand = l.logRand
	config.SessionTicketsDisabled = false
	if config.ClientSessionCache == nil {
		config.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	}
}

func (l *TLSLog) writeLog(conn *tls.Conn, config *tls.Config) error {
	cacheKey := clientSessionCacheKey(conn, config)
	session, ok := config.ClientSessionCache.Get(cacheKey)
	if ok == true {
		// masterSecret is private, use reflect to get its value
		v := reflect.ValueOf(*session)
		y := v.FieldByName("masterSecret")
		// Format: CLIENT_RANDOM <space> <client random> <space> <master secret>
		l.log = fmt.Sprintln("CLIENT_RANDOM", l.logRand.log, hex.EncodeToString(y.Bytes()))
	} else {
		return errors.New("masterSecret not found")
	}

	var logFilePath string
	// If logFile is set, use logFile, otherwise use
	// environment variable SSLKEYLOGFILE.
	// If neither of them is set, throw an error
	if l.logFile == "" {
		sysLogFilePath := os.Getenv("SSLKEYLOGFILE")
		if sysLogFilePath == "" {
			return errors.New("Environment variable SSLKEYLOGFILE not found.")
		}
		logFilePath = sysLogFilePath
	} else {
		logFilePath = l.logFile
	}

	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	io.WriteString(logFile, l.log)
	logFile.Close()

	return nil
}
