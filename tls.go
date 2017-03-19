// Copyright 2017 Mathieu Lonjaret

// package simpletls helps setting up a TLS listener with Let's Encrypt's
// autocert.
package simpletls

import (
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var (
	FlagAutocert = flag.Bool("autocert", true, `Get https certificate from Let's Encrypt. The cached certificate(s) will be in CertCache.`)
)

var (
	TLSKey    = filepath.Join(os.Getenv("HOME"), "keys", "key.pem")
	TLSCert   = filepath.Join(os.Getenv("HOME"), "keys", "cert.pem")
	CertCache = filepath.Join(os.Getenv("HOME"), "keys", "letsencrypt.cache")
)

// Config returns a TLS config for hostport ("hostname:port") that uses autocert
// if FlagAutocert is true, or TLSKey and TLSCert otherwise.
func Config(hostport string) (*tls.Config, error) {
	hostname := hostport
	if strings.Contains(hostname, ":") {
		h, _, err := net.SplitHostPort(hostname)
		if err != nil {
			return nil, err
		}
		hostname = h
	}
	if *FlagAutocert {
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hostname),
			Cache:      autocert.DirCache(CertCache),
		}
		return &tls.Config{
			Rand:           rand.Reader,
			Time:           time.Now,
			NextProtos:     []string{"http/1.1"},
			GetCertificate: m.GetCertificate,
		}, nil
	}
	cert, err := tls.LoadX509KeyPair(TLSCert, TLSKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to load TLS cert: %v", err)
	}
	return &tls.Config{
		Rand:         rand.Reader,
		Time:         time.Now,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{cert},
	}, nil
}

// Listen returns a TLS listen for hostport set up with Config.
func Listen(hostport string) (net.Listener, error) {
	tlsConfig, err := Config(hostport)
	if err != nil {
		return nil, fmt.Errorf("could not configure TLS connection: %v", err)
	}
	listener, err := net.Listen("tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("could not listen on %q: %v", hostport, err)
	}
	return tls.NewListener(listener, tlsConfig), nil
}
