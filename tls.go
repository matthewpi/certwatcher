// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 Matthew Penner

package certwatcher

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/matthewpi/certwatcher/internal/ocsp"
)

// defaultTLSConfig is the default [*tls.Config] for [DefaultTLSConfig].
var defaultTLSConfig = &tls.Config{
	NextProtos: []string{
		"h2",
		"http/1.1",
	},

	CipherSuites: []uint16{
		// TLS 1.0 - 1.2
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

		// TLS 1.3
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	},

	MinVersion: tls.VersionTLS12,
	MaxVersion: tls.VersionTLS13,

	CurvePreferences: []tls.CurveID{
		tls.X25519MLKEM768,
		tls.X25519,
		tls.CurveP256,
	},
}

// DefaultTLSConfig returns a new [*tls.Config] with sensible defaults.
//
// The returned config is a clone, so it can be modified without impacting other
// uses of the config.
//
// The default [*tls.Config] returned here is used by our [TLSConfig] if am
// existing [*tls.Config] is not provided.
func DefaultTLSConfig() *tls.Config {
	return defaultTLSConfig.Clone()
}

// TLSConfig is a wrapper for the stdlib [*tls.Config].
type TLSConfig struct {
	// Config is the [*tls.Config] we are wrapping.
	//
	// DO NOT pass this [*tls.Config] to a server or client, use the
	// [TLSConfig.GetTLSConfig] method instead. If you use this TLS
	// config, it will not have the certificate loaded from CertPath
	// and KeyPath.
	Config *tls.Config

	// CertPath is a path to a TLS certificate.
	//
	// This field is optional, but if set then KeyPath must also be provided.
	CertPath string
	// KeyPath is a path to a TLS private key.
	//
	// This field is optional, but if set then CertPath must also be provided.
	KeyPath string

	// DontStaple controls whether OCSP stapling should be disabled when loading
	// certificates, by default it is enabled.
	DontStaple bool

	// watcher holds a certwatcher instance to manage the reloading of TLS
	// certificate. If both CertPath and KeyPath are provided, a certwatcher
	// will be automatically configured to watch those paths.
	watcher *Watcher

	// tlsConfig holds the actual [*tls.Config] that is returned by
	// [GetTLSConfig].
	//
	// This value will only be initialized after the first call to
	// [GetTLSConfig].
	tlsConfig *tls.Config
}

// GetTLSConfig returns the [*tls.Config] for a listener. If CertPath and
// KeyPath are set, they will be loaded into the returned config, via a
// certwatcher. Otherwise, the [TLSConfig.Config] will be returned unmodified.
//
// Subsequent invocations of this function will return an identical
// [*tls.Config] to the first, avoiding the need to create duplicate
// certwatchers.
func (c *TLSConfig) GetTLSConfig(ctx context.Context) (*tls.Config, error) {
	// Useful in-case the TLSConfig was never initialized, just return nil as
	// there is no TLS config to be provided to the caller.
	if c == nil {
		return nil, nil
	}

	// If we already have the TLS config, return it.
	if c.tlsConfig != nil {
		return c.tlsConfig, nil
	}

	// If both paths are unset, return the manually created *tls.Config.
	if c.CertPath == "" && c.KeyPath == "" {
		return c.Config, nil
	}

	// If either path is unset, error.
	if c.CertPath == "" || c.KeyPath == "" {
		return nil, errors.New("certwatcher: CertPath and KeyPath must both be set or unset together")
	}

	// Get or default the listener's TLS config.
	var tlsConfig *tls.Config
	if c.Config == nil {
		tlsConfig = DefaultTLSConfig()
	} else {
		tlsConfig = c.Config
	}

	// Configure OCSP verification if client auth is configured.
	if tlsConfig.ClientAuth != tls.NoClientCert && tlsConfig.VerifyPeerCertificate != nil {
		tlsConfig.VerifyPeerCertificate = ocsp.VerifyPeerCertificate
	}

	// Load the certificate files through certwatcher to ensure they will be
	// reloaded in the event that they are modified.
	if c.watcher == nil {
		var err error
		c.watcher, err = New(Options{DontStaple: c.DontStaple})
		if err != nil {
			return nil, fmt.Errorf("failed to create certwatcher: %w", err)
		}
	}

	// Attempt to load the certificate files and configure the filesystem
	// watcher.
	if err := c.watcher.Reconfigure(ctx, c.CertPath, c.KeyPath); err != nil {
		return nil, fmt.Errorf("failed to configure certwatcher: %w", err)
	}

	// Start the watcher.
	go c.watcher.Start(ctx)

	// Configure the TLSConfig to use the watcher's GetCertificate.
	tlsConfig.GetCertificate = c.watcher.GetCertificate
	tlsConfig.GetClientCertificate = c.watcher.GetClientCertificate
	c.tlsConfig = tlsConfig
	return c.tlsConfig, nil
}
