// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 Matthew Penner

package ocsp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ErrNoOCSPServer is returned when there are no OCSP servers found on a Certificate.
var ErrNoOCSPServer = errors.New("ocsp: no server in certificate")

// Staple attempts to staple a [tls.Certificate].
func Staple(ctx context.Context, c *tls.Certificate) (*QueryResponse, error) {
	if c.Leaf == nil {
		return nil, errors.New("ocsp: unable to staple certificate with a nil Leaf")
	}

	// Check if the leaf certificate has an OCSP server.
	if len(c.Leaf.OCSPServer) < 1 {
		return nil, ErrNoOCSPServer
	}

	var (
		issuer *x509.Certificate
		err    error
	)
	if len(c.Certificate) == 1 {
		issuer, err = getCertificateIssuer(ctx, c.Leaf)
		if err != nil {
			return nil, err
		}
	} else {
		issuer, err = x509.ParseCertificate(c.Certificate[1])
		if err != nil {
			return nil, err
		}
	}

	// Query the OCSP server.
	res, err := Query(ctx, QueryOpts{
		Certificate: c.Leaf,
		Issuer:      issuer,
		ServerURL:   c.Leaf.OCSPServer[0],
	})
	if err != nil {
		return nil, err
	}

	// Check if the OCSP response is somehow valid even after the certificate would expire.
	if expAt := expiresAt(c.Leaf); res.NextUpdate.After(expAt) {
		return res, fmt.Errorf(`ocsp: response for "%s" valid after certificate expiration (%s)`, c.Leaf.Subject.CommonName, expAt.Sub(res.NextUpdate))
	}

	// If the OCSP status is Good, staple the certificate.
	if res.Status == ocsp.Good {
		c.OCSPStaple = res.Bytes
	}

	// Return the OCSP response.
	return res, nil
}

// getCertificateIssuer attempts to get the issuer of the given leaf certificate by using the first
// IssuingCertificateURL found on the leaf certificate.  If no IssuingCertificateURLs are present
// on the leaf certificate, an error will be returned.
func getCertificateIssuer(ctx context.Context, leaf *x509.Certificate) (*x509.Certificate, error) {
	if len(leaf.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("ocsp: no URL to get issuing certificate with")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, leaf.IssuingCertificateURL[0], nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting issuer certificate: %w", err)
	}
	defer res.Body.Close()

	// Wrap the body with a limit reader to prevent us from reading too much
	// data.
	body := io.LimitReader(res.Body, 1024*1024)

	if expected := http.StatusOK; res.StatusCode != expected {
		b, err := io.ReadAll(body)
		if err == nil {
			return nil, fmt.Errorf("http: expected %d, got %d (%s)", expected, res.StatusCode, string(b))
		}
		return nil, fmt.Errorf("http: expected %d, got %d", expected, res.StatusCode)
	}

	issuerBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("error reading issuer certificate: %w", err)
	}

	issuer, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing issuer certificate: %w", err)
	}
	return issuer, nil
}

// expiresAt return the time that a certificate expires. Account for the 1s
// resolution of ASN.1 UTCTime/GeneralizedTime by including the extra fraction
// of a second of certificate validity beyond the NotAfter value.
func expiresAt(cert *x509.Certificate) time.Time {
	if cert == nil {
		return time.Time{}
	}
	return cert.NotAfter.Truncate(time.Second).Add(1 * time.Second)
}

// IsOCSPFresh returns true if the OCSP response is still fresh.
//
// This is used to determine if we need to fetch and updated response from the
// OCSP server.
func IsOCSPFresh(res *ocsp.Response) bool {
	return time.Now().Before(RefreshTime(res))
}

// RefreshTime returns the refresh time for the OCSP.
func RefreshTime(res *ocsp.Response) time.Time {
	if res == nil {
		return time.Time{}
	}

	nextUpdate := res.NextUpdate

	// If there is an OCSP responder certificate, and it expires before the
	// OCSP response, use its expiration date as the end of the OCSP
	// response's validity period.
	if res.Certificate != nil && res.Certificate.NotAfter.Before(nextUpdate) {
		nextUpdate = res.Certificate.NotAfter
	}

	// Start checking OCSP staple about halfway through validity period for good
	// measure.
	return res.ThisUpdate.Add(nextUpdate.Sub(res.ThisUpdate) / 2)
}
