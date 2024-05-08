// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 Matthew Penner

package ocsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/crypto/ocsp"
)

// VerifyPeerCertificate verifies if a peer certificate is OCSP valid.
func VerifyPeerCertificate(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	if got := len(verifiedChains); got != 1 {
		return fmt.Errorf("ocsp: invalid verified chains (expected 1, got %d)", got)
	}
	if got := len(verifiedChains[0]); got != 2 {
		return fmt.Errorf("ocsp: incorrect number of certificates in chain (expected 2, got %d)", got)
	}
	certificate := verifiedChains[0][0]
	issuer := verifiedChains[0][1]

	// If the certificate doesn't have any OCSP servers, then make the certificate as verified.
	if len(certificate.OCSPServer) < 1 {
		return nil
	}

	// Query the OCSP server for details on the certificate.
	res, err := Query(context.Background(), QueryOpts{
		Certificate: certificate,
		Issuer:      issuer,
		ServerURL:   certificate.OCSPServer[0],
	})
	if err != nil {
		return err
	}
	switch res.Status {
	case ocsp.Good:
		// The certificate is valid.
		return nil
	case ocsp.Revoked:
		// The certificate has been revoked.
		return errors.New("ocsp: certificate has been revoked")
	case ocsp.ServerFailed:
		// Checking the certificate failed.
		// TODO: add an option to allow continuing here.
		return errors.New("ocsp: server failure")
	case ocsp.Unknown:
		fallthrough
	default:
		// Unknown
		return errors.New("ocsp: unknown")
	}
}

// QueryOpts represent the options for a query request.
type QueryOpts struct {
	// Certificate to query information about.
	Certificate *x509.Certificate
	// Issuer to verify the OCSP response against.
	Issuer *x509.Certificate
	// CommonName to use instead of the one specified on the certificate.
	//
	// If empty defaults to Certificate.Subject.CommonName.
	CommonName string
	// ServerURL is the url to the OCSP server for the certificate.
	ServerURL string

	// Hash contains the hash function that should be used when
	// constructing the OCSP request. If zero, SHA-256 will be used.
	Hash crypto.Hash
}

// QueryResponse is the response from an OCSP query.
type QueryResponse struct {
	// Response is the actual OCSP response.
	*ocsp.Response

	// Bytes of the response.
	Bytes []byte
}

// Query attempts to query the OCSP
func Query(ctx context.Context, q QueryOpts) (*QueryResponse, error) {
	// Parse the server url.
	ocspURL, err := url.Parse(q.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing ocsp server url: %w", err)
	}

	// Get the hash from the options, if it is unset, use SHA-256.
	hash := q.Hash
	if hash == 0 {
		hash = crypto.SHA256
	}

	// Create an OCSP request.
	ocspReq, err := ocsp.CreateRequest(q.Certificate, q.Issuer, &ocsp.RequestOptions{Hash: hash})
	if err != nil {
		return nil, fmt.Errorf("error creating ocsp request: %w", err)
	}

	// Create an HTTP request to the OCSP server.
	reader := bytes.NewReader(ocspReq)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, q.ServerURL, reader)
	if err != nil {
		return nil, fmt.Errorf("error creating http request: %w", err)
	}
	req.Header.Set("Accept", "application/ocsp-response")
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Host", ocspURL.Host)

	// Send the OCSP request to the OCSP server.
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error from ocsp server: %w", err)
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

	// Read all the response data.
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("error reading ocsp response: %w", err)
	}

	// Parse and verify the OCSP response.
	ocspRes, err := ParseAndVerifyResponseForCert(data, q.Certificate, q.Issuer)
	if err != nil {
		return nil, fmt.Errorf("error handling ocsp response: %w", err)
	}

	return &QueryResponse{
		Response: ocspRes,
		Bytes:    data,
	}, nil
}

// ParseAndVerifyResponse is like ocsp.ParseResponse but also verifies the
// chain of the OCSP certificate.
//
// ref; https://github.com/golang/go/issues/43522#issuecomment-755389499
func ParseAndVerifyResponse(data []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	return ParseAndVerifyResponseForCert(data, nil, issuer)
}

// ParseAndVerifyResponseForCert is like ocsp.ParseResponseForCert but also
// verifies the chain of the OCSP certificate.
//
// ref; https://github.com/golang/go/issues/43522#issuecomment-755389499
func ParseAndVerifyResponseForCert(data []byte, cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	// Parse the OCSP response.
	ocspRes, err := ocsp.ParseResponseForCert(data, cert, issuer)
	if err != nil {
		return nil, err
	}

	// Verify OCSP responder certificate if it's embedded in the OCSP response.
	if ocspRes.Certificate != nil {
		caPool := x509.NewCertPool()
		caPool.AddCert(issuer)

		// Verify the certificate against the issuer, ensuring that OCSP signing
		// is allowed.
		chains, err := ocspRes.Certificate.Verify(x509.VerifyOptions{
			Roots:     caPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		})
		if err != nil {
			return nil, err
		}

		// 1 chain with 2 certs (leaf and issuer) should be returned
		// on verification success; treat other results as an error.
		if len(chains) < 1 {
			return nil, &VerifyError{Reason: "no matching chains"}
		}
		if len(chains) > 1 {
			return nil, &VerifyError{Reason: "too many matching chains"}
		}
		if len(chains[0]) != 2 {
			return nil, &VerifyError{Reason: "chain mismatch"}
		}
	}

	// Verification was successful.
	return ocspRes, nil
}

// VerifyError represents a OCSP responder verification error.
type VerifyError struct {
	// Reason why the verification failed.
	Reason string
}

func (e *VerifyError) Error() string {
	return "ocsp: responder cert failed verification (" + e.Reason + ")"
}
