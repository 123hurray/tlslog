// Copyright (C) 2015 RayXXZhang
// All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license.  See the LICENSE file for details.

package tlslog

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"
	"testing"
)

func getServerConfig() (*tls.Config, error) {
	ca_b, _ := ioutil.ReadFile("tlsLog.pem")
	block, _ := pem.Decode(ca_b)
	ca, _ := x509.ParseCertificate(block.Bytes)
	priv_b, _ := ioutil.ReadFile("tlsLog.key")
	privBlock, _ := pem.Decode(priv_b)
	priv, _ := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	cert := tls.Certificate{
		Certificate: [][]byte{block.Bytes},
		PrivateKey:  priv,
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	config := tls.Config{
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
	}
	return &config, nil
}

func TestDial(t *testing.T) {
	exitChan := make(chan bool)
	serverConfig, err := getServerConfig()
	if err != nil {
		t.Fatal(err.Error())
	}
	serverListener, err := tls.Listen("tcp", "127.0.0.1:32123", serverConfig)
	if err != nil {
		t.Fatal(err.Error())
	}
	go func() {
		serverConn, err := serverListener.Accept()
		if err != nil {
			close(exitChan)
			t.Fatal(err.Error())
		}
		var buf [5]byte
		serverConn.Read(buf[0:])
		recvStr := string(buf[0:])
		if recvStr != "Hello" {
			close(exitChan)
			t.Fatal("Expected 'Hello', but receive ", recvStr)
		}
		close(exitChan)
	}()
	config := tls.Config{InsecureSkipVerify: true}
	tlsLog, err := NewTLSLog("log.txt")
	if err != nil {
		t.Fatal("Unable to create TlsLog:", err.Error())
	}
	conn, err := tlsLog.Dial("tcp", "127.0.0.1:32123", &config)
	defer conn.Close()

	if err != nil {
		t.Fatal(err.Error())
	}

	conn.Write([]byte("Hello"))
	<-exitChan
}

func TestListen(t *testing.T) {
	exitChan := make(chan bool)
	serverConfig, err := getServerConfig()
	tlsLog, err := NewTLSLog("log.txt")

	if err != nil {
		t.Fatal(err.Error())
	}
	serverListener, err := tlsLog.Listen("tcp", "127.0.0.1:32123", serverConfig)
	if err != nil {
		t.Fatal(err.Error())
	}
	go func() {
		serverConn, err := serverListener.Accept()
		if err != nil {
			close(exitChan)
			t.Fatal(err.Error())
		}
		var buf [5]byte
		serverConn.Read(buf[0:])
		recvStr := string(buf[0:])
		if recvStr != "Hello" {
			close(exitChan)
			t.Fatal("Expected 'Hello', but receive ", recvStr)
		}
		close(exitChan)
	}()
	go func() {
		config := tls.Config{InsecureSkipVerify: true}
		if err != nil {
			t.Fatal("Unable to create TlsLog:", err.Error())
		}
		conn, err := tls.Dial("tcp", "127.0.0.1:32123", &config)
		defer conn.Close()

		if err != nil {
			t.Fatal(err.Error())
		}

		conn.Write([]byte("Hello"))
	}()
	<-exitChan
}

func TestClient(t *testing.T) {
	exitChan := make(chan bool)
	config := tls.Config{InsecureSkipVerify: true}
	tlsLog, err := NewTLSLog("log.txt")
	if err != nil {
		t.Fatal("Unable to create TlsLog:", err.Error())
	}

	c, s := net.Pipe()
	serverConfig, err := getServerConfig()
	if err != nil {
		t.Fatal(err.Error())
	}
	serverConn := tls.Server(s, serverConfig)
	logCli := tlsLog.Client(c, &config)
	go func() {
		err = serverConn.Handshake()
		if err != nil {
			close(exitChan)
			t.Fatal(err.Error())
		}
		var buf [5]byte
		serverConn.Read(buf[0:])
		recvStr := string(buf[0:])
		if recvStr != "Hello" {
			close(exitChan)
			t.Fatal("Expected 'Hello', but receive ", recvStr)
		}
		close(exitChan)
	}()
	go func() {
		c, err = logCli.Handshake()
		if err != nil {
			t.Fatal(err.Error())
		}
		c.Write([]byte("Hello"))
	}()
	<-exitChan
}

func TestServer(t *testing.T) {
	exitChan := make(chan bool)
	config := tls.Config{InsecureSkipVerify: true}
	tlsLog, err := NewTLSLog("log.txt")
	if err != nil {
		t.Fatal("Unable to create TlsLog:", err.Error())
	}
	c, s := net.Pipe()
	serverConfig, err := getServerConfig()
	if err != nil {
		t.Fatal(err.Error())
	}
	tlsConn := tlsLog.Server(s, serverConfig)
	cli := tls.Client(c, &config)

	go func() {

		serverConn, err := tlsConn.Handshake()
		if err != nil {
			close(exitChan)
			t.Fatal(err.Error())
		}
		var buf [5]byte
		serverConn.Read(buf[0:])
		recvStr := string(buf[0:])
		if recvStr != "Hello" {
			close(exitChan)
			t.Fatal("Expected 'Hello', but receive ", recvStr)
		}
		close(exitChan)
	}()
	go func() {
		err = cli.Handshake()

		if err != nil {
			t.Fatal(err.Error())
		}
		cli.Write([]byte("Hello"))
	}()
	<-exitChan
}
