package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

// TestCreateCSR_PermanentIdentifierSAN round-trips a CSR through the encoder
// and parses the SAN otherName back out to confirm the identifier round-trips
// in the byte layout an ACME server expects.
func TestCreateCSR_PermanentIdentifierSAN(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const identifier = "SERIAL-ABC-123"
	csrDER, err := createCSR(key, identifier)
	if err != nil {
		t.Fatalf("createCSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}

	var sanExt *asn1.RawValue
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			sanExt = &asn1.RawValue{FullBytes: ext.Value}
			break
		}
	}
	if sanExt == nil {
		t.Fatal("no subjectAltName extension on CSR")
	}

	// SubjectAltName ::= SEQUENCE OF GeneralName
	var generalNames []asn1.RawValue
	if _, err := asn1.Unmarshal(sanExt.FullBytes, &generalNames); err != nil {
		t.Fatalf("unmarshal SAN sequence: %v", err)
	}
	if len(generalNames) != 1 {
		t.Fatalf("expected 1 GeneralName, got %d", len(generalNames))
	}

	gn := generalNames[0]
	if gn.Class != 2 || gn.Tag != 0 || !gn.IsCompound {
		t.Fatalf("GeneralName not [0] IMPLICIT context-specific constructed: class=%d tag=%d compound=%v",
			gn.Class, gn.Tag, gn.IsCompound)
	}

	// Re-tag from [0] IMPLICIT (0xa0) back to SEQUENCE (0x30) for decoding.
	otherNameSeq := append([]byte(nil), gn.FullBytes...)
	otherNameSeq[0] = 0x30
	var on struct {
		TypeID asn1.ObjectIdentifier
		Value  asn1.RawValue `asn1:"tag:0,explicit"`
	}
	if _, err := asn1.Unmarshal(otherNameSeq, &on); err != nil {
		t.Fatalf("unmarshal OtherName: %v", err)
	}
	if !on.TypeID.Equal(oidPermanentIdentifier) {
		t.Fatalf("OtherName type-id = %v, want %v", on.TypeID, oidPermanentIdentifier)
	}

	var pid struct {
		Value string `asn1:"utf8"`
	}
	if _, err := asn1.Unmarshal(on.Value.Bytes, &pid); err != nil {
		t.Fatalf("unmarshal PermanentIdentifier: %v", err)
	}
	if pid.Value != identifier {
		t.Fatalf("PermanentIdentifier = %q, want %q", pid.Value, identifier)
	}
}
