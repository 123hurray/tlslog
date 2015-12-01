#TLSLog

[![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/123hurray/tlslog/master/LICENSE)

## Introduction
TLSLog is a Golang library used to debug SSL application data for Wireshark.

If ECDHE is used in Key-Exchange, Wireshark cannot decrypt the application data only by set the server private key.
But Wireshark supports [NSS key log format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format) that store all information
needed in application data decryption process.

NSS key log format is supported by Chrome and Firefox but not Golang.
When using Golang `crypto/tls` library, it's difficult to debug encrypted data sent and received by SSL.

But Golang `crypto/tls` library does store these information internally.
Thus, TLSLog hooks `config.Rand` and uses reflection to get master secret from `crypto/tls` library.

**CAUTION：Only client side function is implemented, which means that TLSLog can not be used to build a SSL server.**

## Usage

### Install

```shell
go get github.com/123hurray/tlslog/tlslog.go
```

### Dial

`Dial` is the most commonly way to build an SSL client.

```go
config := tls.Config{InsecureSkipVerify: true}

// Get a TLSLog
tlsLog, err := NewTLSLog("log.txt")
if err != nil {
	fmt.Println("Unable to create TlsLog:", err.Error())
}

// Use TLSLog.Dial instead of tls.Dial
conn, err := tlsLog.Dial("tcp", "127.0.0.1:32123", &config)

// conn is tls.Conn, just used as is documented in tls library
```

### Client

`Client` is another way to build an SSL client.

```go
config := tls.Config{InsecureSkipVerify: true}
tlsLog, err := NewTLSLog("log.txt")
// Make net.conn
c, s := net.Pipe()
// use TLSLog.Client instead of tls.Client
logCli := tlsLog.Client(c, &config)
// Do handshake
conn, err = logCli.Handshake()
// conn is tls.Conn, just used as is documented in tls library
```

## Decrypt application data using Wireshark

See the articles below:

* [Wireshark WIKI:Using the (Pre)-Master-Secret](https://wiki.wireshark.org/SSL#Using_the_.28Pre.29-Master-Secret)
* [Decrypting TLS Browser Traffic With Wireshark – The Easy Way!](https://jimshaver.net/2015/02/11/decrypting-tls-browser-traffic-with-wireshark-the-easy-way/)


## TODO

* Server side key log