package main

import (
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
)

// attester creates attestation objects for the ACME device-attest-01 challenge.
type attester interface {
	// attestationObject creates a CBOR-encoded WebAuthn attestation object
	// for the given challenge token.
	attestationObject(token string) ([]byte, error)
	close() error
}

// attestationObject is the WebAuthn attestation object structure (CBOR-encoded).
type attestationObject struct {
	Format  string         `cbor:"fmt"`
	AttStmt map[string]any `cbor:"attStmt"`
}

// --- Null attester (--software-key mode, dev/test only) ---
// Produces fmt:"null" attestation. Only works against a nanoca server with the
// null verifier enabled (not suitable for production).

type nullAttester struct{}

func (a *nullAttester) attestationObject(token string) ([]byte, error) {
	return cbor.Marshal(attestationObject{
		Format:  "null",
		AttStmt: map[string]any{},
	})
}

func (a *nullAttester) close() error { return nil }

// --- TPM 2.0 attester ---
// Uses google/go-attestation to open the TPM, create an AK, and produce
// a TPM quote with the challenge nonce in TPMS_ATTEST.extraData.
//
// x5c chain: uses EK certificates from the TPM, which chain to manufacturer
// roots (Intel, AMD, Infineon, etc.). The quote is signed by the AK.
//
// Known limitation: the x5c[0] cert is the EK, but the signature is from
// the AK. End-to-end verification requires the nanoca TPM verifier to
// support credential activation linking the AK to the EK. For TPMs with
// pre-provisioned IAK certificates (Intel vPro, etc.), x5c[0] would be
// the IAK cert and verification works directly.

type tpmAttester struct {
	logger  *slog.Logger
	tpm     *attest.TPM
	ak      *attest.AK
	ekCerts [][]byte // DER-encoded EK certs for x5c
	serial  string
}

func newTPMAttester(logger *slog.Logger, serial string) (*tpmAttester, error) {
	tpm, err := attest.OpenTPM(&attest.OpenConfig{})
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}

	ak, err := tpm.NewAK(&attest.AKConfig{})
	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("creating AK: %w", err)
	}

	// Read EK certificates for the x5c chain.
	var ekDER [][]byte
	eks, err := tpm.EKs()
	if err != nil {
		logger.Warn("could not read EK certificates", "error", err)
	}
	for _, ek := range eks {
		if ek.Certificate != nil {
			ekDER = append(ekDER, ek.Certificate.Raw)
		}
	}

	return &tpmAttester{
		logger:  logger,
		tpm:     tpm,
		ak:      ak,
		ekCerts: ekDER,
		serial:  serial,
	}, nil
}

func (a *tpmAttester) attestationObject(token string) ([]byte, error) {
	if len(a.ekCerts) == 0 {
		return nil, fmt.Errorf("no EK certificates available; TPM may need EK provisioning")
	}

	// device-attest-01 nonce = SHA256(token).
	nonce := sha256.Sum256([]byte(token))

	quote, err := a.ak.Quote(a.tpm, nonce[:], attest.HashSHA256)
	if err != nil {
		return nil, fmt.Errorf("TPM quote: %w", err)
	}

	// Build x5c as []any per CBOR/WebAuthn convention.
	x5c := make([]any, len(a.ekCerts))
	for i, der := range a.ekCerts {
		x5c[i] = der
	}

	// Default to RS256 (COSE -257); most TPM AKs are RSA 2048.
	alg := int64(-257)

	obj := attestationObject{
		Format: "tpm",
		AttStmt: map[string]any{
			"x5c":      x5c,
			"certInfo": quote.Quote,
			"sig":      quote.Signature,
			"alg":      alg,
			"serial":   a.serial,
		},
	}

	a.logger.Info("TPM attestation created", "serial", a.serial, "ek_certs", len(a.ekCerts))
	return cbor.Marshal(obj)
}

func (a *tpmAttester) close() error {
	if a.ak != nil {
		a.ak.Close(a.tpm)
	}
	if a.tpm != nil {
		return a.tpm.Close()
	}
	return nil
}
