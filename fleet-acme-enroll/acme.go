package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type acmeClient struct {
	logger     *slog.Logger
	http       *http.Client
	accountKey *ecdsa.PrivateKey
	baseURL    string

	dir        acmeDirectory
	accountURL string
	nonce      string
}

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type acmeOrder struct {
	URL            string   `json:"-"` // from Location header
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

type acmeAuthz struct {
	Status     string          `json:"status"`
	Challenges []acmeChallenge `json:"challenges"`
}

type acmeChallenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Status string `json:"status"`
	Token  string `json:"token"`
}

func newACMEClient(logger *slog.Logger, baseURL string, key *ecdsa.PrivateKey) *acmeClient {
	return &acmeClient{
		logger:     logger,
		http:       &http.Client{Timeout: 30 * time.Second},
		accountKey: key,
		baseURL:    baseURL,
	}
}

// enroll runs the full ACME device-attest-01 flow and returns the issued
// certificate chain in PEM format.
func (c *acmeClient) enroll(identifier string, csrKey *ecdsa.PrivateKey, att attester) ([]byte, error) {
	// Directory + nonce + account.
	if err := c.discover(); err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if err := c.getNonce(); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	if err := c.newAccount(); err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}

	// Create order.
	order, err := c.newOrder(identifier)
	if err != nil {
		return nil, fmt.Errorf("order: %w", err)
	}
	if len(order.Authorizations) == 0 {
		return nil, fmt.Errorf("order has no authorizations")
	}

	// Get authorization and find device-attest-01 challenge.
	authz, err := c.getAuthz(order.Authorizations[0])
	if err != nil {
		return nil, fmt.Errorf("authorization: %w", err)
	}
	ch := findChallenge(authz.Challenges, "device-attest-01")
	if ch == nil {
		return nil, fmt.Errorf("no device-attest-01 challenge in authorization")
	}

	// Create attestation and respond to challenge.
	attObj, err := att.attestationObject(ch.Token)
	if err != nil {
		return nil, fmt.Errorf("creating attestation: %w", err)
	}
	if err := c.respondChallenge(ch.URL, attObj); err != nil {
		return nil, fmt.Errorf("challenge response: %w", err)
	}

	// Poll until challenge is validated.
	if err := c.pollStatus(ch.URL, func(body []byte) string {
		var v acmeChallenge
		json.Unmarshal(body, &v)
		return v.Status
	}); err != nil {
		return nil, fmt.Errorf("challenge validation: %w", err)
	}
	c.logger.Info("challenge validated")

	// Finalize order with CSR.
	csrDER, err := createCSR(csrKey, identifier)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}
	if err := c.finalizeOrder(order.Finalize, csrDER); err != nil {
		return nil, fmt.Errorf("finalize: %w", err)
	}

	// Poll order until certificate is ready.
	var certURL string
	if err := c.pollStatus(order.URL, func(body []byte) string {
		var o acmeOrder
		json.Unmarshal(body, &o)
		certURL = o.Certificate
		return o.Status
	}); err != nil {
		return nil, fmt.Errorf("order completion: %w", err)
	}
	if certURL == "" {
		return nil, fmt.Errorf("order valid but no certificate URL")
	}

	// Download certificate.
	certPEM, err := c.downloadCert(certURL)
	if err != nil {
		return nil, fmt.Errorf("downloading certificate: %w", err)
	}

	c.logger.Info("certificate issued")
	return certPEM, nil
}

func (c *acmeClient) discover() error {
	resp, err := c.http.Get(c.baseURL + "/directory")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("directory returned %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(&c.dir)
}

func (c *acmeClient) getNonce() error {
	resp, err := c.http.Head(c.dir.NewNonce)
	if err != nil {
		return err
	}
	resp.Body.Close()
	c.nonce = resp.Header.Get("Replay-Nonce")
	if c.nonce == "" {
		return fmt.Errorf("no Replay-Nonce header")
	}
	return nil
}

func (c *acmeClient) newAccount() error {
	payload := map[string]any{"termsOfServiceAgreed": true}
	resp, err := c.signedPost(c.dir.NewAccount, payload, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return c.readError(resp)
	}
	c.accountURL = resp.Header.Get("Location")
	if c.accountURL == "" {
		return fmt.Errorf("no Location header in account response")
	}
	c.logger.Info("ACME account created", "url", c.accountURL)
	return nil
}

func (c *acmeClient) newOrder(identifier string) (*acmeOrder, error) {
	payload := map[string]any{
		"identifiers": []map[string]string{
			{"type": "permanent-identifier", "value": identifier},
		},
	}
	resp, err := c.signedPost(c.dir.NewOrder, payload, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return nil, c.readError(resp)
	}
	var order acmeOrder
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		return nil, err
	}
	order.URL = resp.Header.Get("Location")
	c.logger.Info("order created", "status", order.Status, "url", order.URL)
	return &order, nil
}

func (c *acmeClient) getAuthz(url string) (*acmeAuthz, error) {
	resp, err := c.signedPost(url, nil, false) // POST-as-GET
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, c.readError(resp)
	}
	var authz acmeAuthz
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		return nil, err
	}
	return &authz, nil
}

func (c *acmeClient) respondChallenge(url string, attObj []byte) error {
	payload := map[string]string{
		"attObj": base64.RawURLEncoding.EncodeToString(attObj),
	}
	resp, err := c.signedPost(url, payload, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return c.readError(resp)
	}
	return nil
}

func (c *acmeClient) finalizeOrder(url string, csrDER []byte) error {
	payload := map[string]string{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	}
	resp, err := c.signedPost(url, payload, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return c.readError(resp)
	}
	return nil
}

func (c *acmeClient) downloadCert(url string) ([]byte, error) {
	resp, err := c.signedPost(url, nil, false) // POST-as-GET
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, c.readError(resp)
	}
	return io.ReadAll(resp.Body)
}

// pollStatus polls a URL via POST-as-GET until the status is "valid" or
// "invalid", using the provided function to extract the status from the
// response body.
func (c *acmeClient) pollStatus(url string, extractStatus func([]byte) string) error {
	for i := 0; i < 30; i++ {
		resp, err := c.signedPost(url, nil, false)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		status := extractStatus(body)
		switch status {
		case "valid":
			return nil
		case "invalid":
			return fmt.Errorf("status invalid: %s", body)
		case "pending", "processing", "ready":
			time.Sleep(2 * time.Second)
		default:
			return fmt.Errorf("unexpected status %q: %s", status, body)
		}
	}
	return fmt.Errorf("polling timed out after 60s")
}

// signedPost sends a JWS-signed POST to url. If embedJWK is true, the public
// key is embedded in the header (for new-account). Otherwise, the kid
// (account URL) is used. A nil payload means POST-as-GET (empty payload).
func (c *acmeClient) signedPost(url string, payload any, embedJWK bool) (*http.Response, error) {
	var payloadBytes []byte
	if payload == nil {
		payloadBytes = []byte{} // POST-as-GET: empty payload
	} else {
		var err error
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshaling payload: %w", err)
		}
	}

	opts := new(jose.SignerOptions)
	opts.WithHeader(jose.HeaderKey("nonce"), c.nonce)
	opts.WithHeader(jose.HeaderKey("url"), url)

	var signingKey jose.SigningKey
	if embedJWK {
		opts.EmbedJWK = true
		signingKey = jose.SigningKey{Algorithm: jose.ES256, Key: c.accountKey}
	} else {
		signingKey = jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       &jose.JSONWebKey{Key: c.accountKey, KeyID: c.accountURL},
		}
	}

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return nil, fmt.Errorf("creating JWS signer: %w", err)
	}

	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("JWS signing: %w", err)
	}

	resp, err := c.http.Post(url, "application/jose+json",
		bytes.NewReader([]byte(jws.FullSerialize())))
	if err != nil {
		return nil, err
	}

	// Capture nonce from every response.
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}
	return resp, nil
}

func (c *acmeClient) readError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
}

func findChallenge(challenges []acmeChallenge, typ string) *acmeChallenge {
	for i := range challenges {
		if challenges[i].Type == typ {
			return &challenges[i]
		}
	}
	return nil
}

func createCSR(key *ecdsa.PrivateKey, identifier string) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: identifier},
	}, key)
}
