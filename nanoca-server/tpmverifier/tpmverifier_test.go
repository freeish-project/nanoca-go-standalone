package tpmverifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// buildTestTPMSAttest creates a minimal TPMS_ATTEST structure with the given
// nonce in extraData and a dummy qualifiedSigner.
func buildTestTPMSAttest(nonce []byte) []byte {
	var buf []byte

	// Magic: TPM_GENERATED_VALUE
	buf = binary.BigEndian.AppendUint32(buf, tpmGeneratedMagic)
	// Type: TPM_ST_ATTEST_CERTIFY
	buf = binary.BigEndian.AppendUint16(buf, tpmStCertify)

	// qualifiedSigner (TPM2B): 4 bytes of dummy data
	signer := []byte{0x01, 0x02, 0x03, 0x04}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(signer)))
	buf = append(buf, signer...)

	// extraData (TPM2B): the nonce
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(nonce)))
	buf = append(buf, nonce...)

	// clockInfo (17 bytes) + firmwareVersion (8 bytes) = 25 bytes of padding
	buf = append(buf, make([]byte, 25)...)

	return buf
}

// testCAAndAIK creates a self-signed CA and an AIK cert signed by it.
func testCAAndAIK(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TPM Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	aikKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aikTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test AIK"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caCert, _ := x509.ParseCertificate(caCertDER)
	aikCertDER, err := x509.CreateCertificate(rand.Reader, aikTemplate, caCert, &aikKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	return caCert, aikKey, caCertDER, aikCertDER
}

// writeTestRoots writes a CA cert as PEM to a temp dir and returns the dir path.
func writeTestRoots(t *testing.T, caCertDER []byte) string {
	t.Helper()
	dir := t.TempDir()
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(filepath.Join(dir, "test-root.pem"), pemData, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func signECDSARaw(key *ecdsa.PrivateKey, hash crypto.Hash, data []byte) ([]byte, error) {
	h := hash.New()
	h.Write(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	keySize := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*keySize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)
	return sig, nil
}

func TestVerify_ValidAttestation(t *testing.T) {
	_, aikKey, caCertDER, aikCertDER := testCAAndAIK(t)
	rootsDir := writeTestRoots(t, caCertDER)

	challenge := []byte("test-challenge-token")
	nonce := sha256.Sum256(challenge)
	certInfo := buildTestTPMSAttest(nonce[:])

	sig, err := signECDSARaw(aikKey, crypto.SHA256, certInfo)
	if err != nil {
		t.Fatal(err)
	}

	stmt := nanoca.AttestationStatement{
		Format: "tpm",
		AttStmt: map[string]any{
			"x5c":      []any{aikCertDER},
			"certInfo": certInfo,
			"sig":      sig,
			"alg":      int64(coseAlgES256),
			"serial":   "TEST-SERIAL-123",
		},
	}

	v := New(testLogger(), rootsDir)
	info, err := v.Verify(context.Background(), stmt, challenge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.PermanentIdentifier == nil || info.PermanentIdentifier.Identifier != "TEST-SERIAL-123" {
		t.Fatalf("expected serial TEST-SERIAL-123, got %+v", info.PermanentIdentifier)
	}
}

func TestVerify_FallbackIdentifier(t *testing.T) {
	_, aikKey, caCertDER, aikCertDER := testCAAndAIK(t)
	rootsDir := writeTestRoots(t, caCertDER)

	challenge := []byte("test")
	nonce := sha256.Sum256(challenge)
	certInfo := buildTestTPMSAttest(nonce[:])
	sig, _ := signECDSARaw(aikKey, crypto.SHA256, certInfo)

	stmt := nanoca.AttestationStatement{
		Format: "tpm",
		AttStmt: map[string]any{
			"x5c":      []any{aikCertDER},
			"certInfo": certInfo,
			"sig":      sig,
			"alg":      int64(coseAlgES256),
			// No "serial" field -- should fall back to AIK pubkey hash.
		},
	}

	v := New(testLogger(), rootsDir)
	info, err := v.Verify(context.Background(), stmt, challenge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.PermanentIdentifier == nil || info.PermanentIdentifier.Identifier == "" {
		t.Fatal("expected fallback identifier, got empty")
	}
	// Should be a hex-encoded SHA256 hash (64 chars).
	if len(info.PermanentIdentifier.Identifier) != 64 {
		t.Fatalf("expected 64-char hex hash, got %d chars: %s",
			len(info.PermanentIdentifier.Identifier), info.PermanentIdentifier.Identifier)
	}
}

func TestVerify_WrongFormat(t *testing.T) {
	v := New(testLogger(), t.TempDir())
	stmt := nanoca.AttestationStatement{Format: "apple"}
	_, err := v.Verify(context.Background(), stmt, nil)
	if err == nil {
		t.Fatal("expected error for wrong format")
	}
}

func TestVerify_BadNonce(t *testing.T) {
	_, aikKey, caCertDER, aikCertDER := testCAAndAIK(t)
	rootsDir := writeTestRoots(t, caCertDER)

	wrongNonce := sha256.Sum256([]byte("wrong"))
	certInfo := buildTestTPMSAttest(wrongNonce[:])
	sig, _ := signECDSARaw(aikKey, crypto.SHA256, certInfo)

	stmt := nanoca.AttestationStatement{
		Format: "tpm",
		AttStmt: map[string]any{
			"x5c":      []any{aikCertDER},
			"certInfo": certInfo,
			"sig":      sig,
			"alg":      int64(coseAlgES256),
		},
	}

	v := New(testLogger(), rootsDir)
	_, err := v.Verify(context.Background(), stmt, []byte("correct-challenge"))
	if err == nil {
		t.Fatal("expected nonce mismatch error")
	}
}

func TestVerify_UntrustedChain(t *testing.T) {
	_, aikKey, _, aikCertDER := testCAAndAIK(t)

	// Write a different CA as the trusted root.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Other CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	otherDER, _ := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)
	rootsDir := writeTestRoots(t, otherDER)

	challenge := []byte("test")
	nonce := sha256.Sum256(challenge)
	certInfo := buildTestTPMSAttest(nonce[:])
	sig, _ := signECDSARaw(aikKey, crypto.SHA256, certInfo)

	stmt := nanoca.AttestationStatement{
		Format: "tpm",
		AttStmt: map[string]any{
			"x5c":      []any{aikCertDER},
			"certInfo": certInfo,
			"sig":      sig,
			"alg":      int64(coseAlgES256),
		},
	}

	v := New(testLogger(), rootsDir)
	_, err := v.Verify(context.Background(), stmt, challenge)
	if err == nil {
		t.Fatal("expected chain verification error")
	}
}

func TestVerify_NoRoots(t *testing.T) {
	v := New(testLogger(), filepath.Join(t.TempDir(), "nonexistent"))
	stmt := nanoca.AttestationStatement{
		Format: "tpm",
		AttStmt: map[string]any{
			"x5c": []any{[]byte{0x30, 0x00}},
		},
	}
	_, err := v.Verify(context.Background(), stmt, []byte("test"))
	if err == nil {
		t.Fatal("expected error for no roots")
	}
}

func TestParseTPMSAttest_ValidCertify(t *testing.T) {
	nonce := []byte("test-nonce-32-bytes-exactly-here")
	data := buildTestTPMSAttest(nonce)
	attest, err := parseTPMSAttest(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(attest.extraData) != string(nonce) {
		t.Fatalf("nonce mismatch: got %x, want %x", attest.extraData, nonce)
	}
	if len(attest.qualifiedSigner) != 4 {
		t.Fatalf("expected 4-byte qualifiedSigner, got %d", len(attest.qualifiedSigner))
	}
}

func TestParseTPMSAttest_BadMagic(t *testing.T) {
	data := make([]byte, 32)
	binary.BigEndian.PutUint32(data[0:4], 0xdeadbeef)
	_, err := parseTPMSAttest(data)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestParseTPMSAttest_TooShort(t *testing.T) {
	_, err := parseTPMSAttest([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}
