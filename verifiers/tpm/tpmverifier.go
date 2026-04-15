// Package tpmverifier implements a nanoca AttestationVerifier for TPM 2.0
// attestation. It validates AIK certificate chains against trusted TPM
// manufacturer root CAs, verifies certify signatures, and checks the nonce
// in TPMS_ATTEST.extraData against SHA256(challenge).
package tpm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/brandonweeks/nanoca"
)

const (
	// tpmGeneratedMagic is TPM_GENERATED_VALUE (0xff544347 = "\xffTCG").
	tpmGeneratedMagic = 0xff544347

	// tpmStCertify is TPM_ST_ATTEST_CERTIFY.
	tpmStCertify = 0x8017

	// tpmStQuote is TPM_ST_ATTEST_QUOTE.
	tpmStQuote = 0x8018
)

// COSE algorithm identifiers.
const (
	coseAlgRS256 = -257
	coseAlgRS384 = -258
	coseAlgRS512 = -259
	coseAlgES256 = -7
	coseAlgES384 = -35
	coseAlgES512 = -36
)

// OID for hardware module name (RFC 4108).
var oidHardwareModuleName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}

// AttestationVerifier verifies TPM 2.0 attestation statements.
type AttestationVerifier struct {
	logger   *slog.Logger
	rootsDir string
}

// New creates a TPM attestation verifier. rootsDir is the directory containing
// PEM-encoded TPM vendor root CA certificates (populated by FetchRoots).
func New(logger *slog.Logger, rootsDir string) *AttestationVerifier {
	return &AttestationVerifier{
		logger:   logger,
		rootsDir: rootsDir,
	}
}

// Format returns the attestation format identifier.
func (v *AttestationVerifier) Format() string { return "tpm" }

// Verify validates a TPM attestation statement and returns device identity.
//
// Expected attStmt fields:
//   - x5c: []any ([]byte DER certs) -- AIK certificate chain
//   - certInfo: []byte -- TPMS_ATTEST structure
//   - sig: []byte -- signature over certInfo by the AIK
//   - alg: int64 -- COSE signing algorithm identifier
//   - serial: string -- device DMI serial number (for PermanentIdentifier)
func (v *AttestationVerifier) Verify(ctx context.Context, stmt nanoca.AttestationStatement, challenge []byte) (*nanoca.DeviceInfo, error) {
	if stmt.Format != "tpm" {
		return nil, fmt.Errorf("format mismatch: expected tpm, got %s", stmt.Format)
	}

	// Parse AIK certificate chain.
	certChain, err := parseX5C(stmt.AttStmt)
	if err != nil {
		return nil, fmt.Errorf("parsing x5c: %w", err)
	}

	// Load trusted roots from disk.
	roots, count, err := LoadRootsFromDir(v.rootsDir)
	if err != nil {
		return nil, fmt.Errorf("loading TPM roots: %w", err)
	}
	if count == 0 {
		return nil, errors.New("no TPM vendor root CAs loaded; run FetchRoots first")
	}

	// Verify certificate chain.
	if err := verifyCertChain(certChain, roots); err != nil {
		return nil, fmt.Errorf("certificate chain verification: %w", err)
	}

	aikPub := certChain[0].PublicKey

	// Extract and validate certInfo + signature.
	certInfo, err := extractBytes(stmt.AttStmt, "certInfo")
	if err != nil {
		return nil, fmt.Errorf("extracting certInfo: %w", err)
	}
	sig, err := extractBytes(stmt.AttStmt, "sig")
	if err != nil {
		return nil, fmt.Errorf("extracting sig: %w", err)
	}
	alg, err := extractInt(stmt.AttStmt, "alg")
	if err != nil {
		return nil, fmt.Errorf("extracting alg: %w", err)
	}

	// Verify signature over certInfo.
	if err := verifySignature(aikPub, certInfo, sig, alg); err != nil {
		return nil, fmt.Errorf("signature verification: %w", err)
	}

	// Parse TPMS_ATTEST and verify nonce.
	attest, err := parseTPMSAttest(certInfo)
	if err != nil {
		return nil, fmt.Errorf("parsing TPMS_ATTEST: %w", err)
	}

	expectedNonce := sha256.Sum256(challenge)
	if subtle.ConstantTimeCompare(attest.extraData, expectedNonce[:]) != 1 {
		return nil, errors.New("nonce mismatch in TPMS_ATTEST.extraData")
	}

	// Extract device serial from attStmt (provided by enrollment client).
	serial, _ := stmt.AttStmt["serial"].(string)
	if serial == "" {
		// Fall back to hex-encoded SHA256 of AIK public key as stable identifier.
		aikDER, err := x509.MarshalPKIXPublicKey(aikPub)
		if err == nil {
			h := sha256.Sum256(aikDER)
			serial = fmt.Sprintf("%x", h)
		}
	}

	v.logger.InfoContext(ctx, "TPM attestation verified", "serial", serial)

	return &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{
			Identifier: serial,
		},
		HardwareModule: &nanoca.HardwareModule{
			Type:  oidHardwareModuleName,
			Value: attest.qualifiedSigner,
		},
	}, nil
}

// tpmsAttest holds parsed fields from a TPMS_ATTEST structure.
type tpmsAttest struct {
	extraData       []byte
	qualifiedSigner []byte
}

// parseTPMSAttest parses the relevant fields from a TPMS_ATTEST byte slice.
// Layout (TPM 2.0 Part 2, Section 10.12.8):
//
//	magic (4 bytes) | type (2 bytes) | qualifiedSigner (TPM2B) |
//	extraData (TPM2B) | clockInfo (17 bytes) | firmwareVersion (8 bytes) |
//	attested (type-specific)
func parseTPMSAttest(data []byte) (*tpmsAttest, error) {
	if len(data) < 6 {
		return nil, errors.New("TPMS_ATTEST too short")
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != tpmGeneratedMagic {
		return nil, fmt.Errorf("invalid TPM_GENERATED magic: 0x%08x", magic)
	}

	stType := binary.BigEndian.Uint16(data[4:6])
	if stType != tpmStCertify && stType != tpmStQuote {
		return nil, fmt.Errorf("unsupported TPMS_ATTEST type: 0x%04x", stType)
	}

	offset := 6

	// qualifiedSigner is a TPM2B (2-byte length prefix + data).
	qualifiedSigner, n, err := readTPM2B(data, offset)
	if err != nil {
		return nil, fmt.Errorf("reading qualifiedSigner: %w", err)
	}
	offset += n

	// extraData is a TPM2B.
	extraData, _, err := readTPM2B(data, offset)
	if err != nil {
		return nil, fmt.Errorf("reading extraData: %w", err)
	}

	return &tpmsAttest{
		extraData:       extraData,
		qualifiedSigner: qualifiedSigner,
	}, nil
}

// readTPM2B reads a TPM2B structure (2-byte big-endian length + data) at
// offset. Returns the data bytes and total bytes consumed.
func readTPM2B(data []byte, offset int) ([]byte, int, error) {
	if offset+2 > len(data) {
		return nil, 0, errors.New("TPM2B: buffer too short for length")
	}
	size := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	if offset+2+size > len(data) {
		return nil, 0, fmt.Errorf("TPM2B: buffer too short for %d bytes of data", size)
	}
	return data[offset+2 : offset+2+size], 2 + size, nil
}

func parseX5C(attStmt map[string]any) ([]*x509.Certificate, error) {
	x5cRaw, ok := attStmt["x5c"]
	if !ok {
		return nil, errors.New("missing x5c field")
	}
	x5cSlice, ok := x5cRaw.([]any)
	if !ok {
		return nil, errors.New("x5c must be an array")
	}
	if len(x5cSlice) == 0 {
		return nil, errors.New("x5c array is empty")
	}

	var chain []*x509.Certificate
	for i, raw := range x5cSlice {
		der, ok := raw.([]byte)
		if !ok {
			return nil, fmt.Errorf("x5c[%d] must be a byte slice", i)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c[%d]: %w", i, err)
		}
		chain = append(chain, cert)
	}

	return chain, nil
}

func verifyCertChain(chain []*x509.Certificate, roots *x509.CertPool) error {
	if len(chain) == 0 {
		return errors.New("empty certificate chain")
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func verifySignature(pub crypto.PublicKey, data, sig []byte, alg int64) error {
	switch alg {
	case coseAlgRS256:
		return verifyRSA(pub, crypto.SHA256, data, sig)
	case coseAlgRS384:
		return verifyRSA(pub, crypto.SHA384, data, sig)
	case coseAlgRS512:
		return verifyRSA(pub, crypto.SHA512, data, sig)
	case coseAlgES256:
		return verifyECDSA(pub, crypto.SHA256, elliptic.P256(), data, sig)
	case coseAlgES384:
		return verifyECDSA(pub, crypto.SHA384, elliptic.P384(), data, sig)
	case coseAlgES512:
		return verifyECDSA(pub, crypto.SHA512, elliptic.P521(), data, sig)
	default:
		return fmt.Errorf("unsupported COSE algorithm: %d", alg)
	}
}

func verifyRSA(pub crypto.PublicKey, hash crypto.Hash, data, sig []byte) error {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("AIK public key is not RSA")
	}
	h := hash.New()
	h.Write(data)
	return rsa.VerifyPKCS1v15(rsaPub, hash, h.Sum(nil), sig)
}

func verifyECDSA(pub crypto.PublicKey, hash crypto.Hash, curve elliptic.Curve, data, sig []byte) error {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("AIK public key is not ECDSA")
	}
	if ecPub.Curve != curve {
		return fmt.Errorf("curve mismatch: expected %s, got %s", curve.Params().Name, ecPub.Curve.Params().Name)
	}
	h := hash.New()
	h.Write(data)

	// TPM ECDSA signatures are raw r||s, not ASN.1 DER.
	keySize := (curve.Params().BitSize + 7) / 8
	if len(sig) == 2*keySize {
		r := new(big.Int).SetBytes(sig[:keySize])
		s := new(big.Int).SetBytes(sig[keySize:])
		if ecdsa.Verify(ecPub, h.Sum(nil), r, s) {
			return nil
		}
		return errors.New("ECDSA signature verification failed")
	}

	// Try ASN.1 DER format as fallback.
	if ecdsa.VerifyASN1(ecPub, h.Sum(nil), sig) {
		return nil
	}
	return errors.New("ECDSA signature verification failed")
}

func extractBytes(m map[string]any, key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("missing %s field", key)
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("%s must be a byte slice", key)
	}
	return b, nil
}

func extractInt(m map[string]any, key string) (int64, error) {
	v, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("missing %s field", key)
	}
	switch n := v.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case float64:
		return int64(n), nil
	case uint64:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("%s must be a number, got %T", key, v)
	}
}
