// fleet-acme-enroll is a Linux device certificate enrollment client for nanoca.
//
// It performs the ACME device-attest-01 flow using TPM 2.0 attestation (or a
// software key for dev/test) and installs the issued certificate into nssdb
// for WARP mTLS. Designed to run as a Fleet Setup Experience script.
//
// Usage:
//
//	fleet-acme-enroll --nanoca-url https://ca.example.com/acme
//	fleet-acme-enroll --nanoca-url https://ca.example.com/acme --software-key
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	var (
		flNanoCA      = flag.String("nanoca-url", envOr("NANOCA_URL", ""), "nanoca ACME base URL (e.g., https://ca.example.com/acme)")
		flIdentifier  = flag.String("identifier", "", "device permanent identifier (default: auto-detect from DMI serial)")
		flSoftwareKey = flag.Bool("software-key", false, "use software key with null attestation (dev/test only)")
		flCertDir     = flag.String("cert-dir", "/etc/fleet-certs", "directory for cert and key storage")
		flNSSDB       = flag.String("nssdb", "/etc/pki/nssdb", "nssdb path for WARP certificate installation")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *flNanoCA == "" {
		logger.Error("--nanoca-url is required")
		os.Exit(1)
	}

	// Detect device identifier.
	identifier := *flIdentifier
	if identifier == "" {
		var err error
		identifier, err = readDMISerial()
		if err != nil {
			logger.Error("auto-detecting device serial failed; use --identifier", "error", err)
			os.Exit(1)
		}
	}
	logger.Info("device identifier", "identifier", identifier)

	// Check for existing valid certificate.
	certPath := filepath.Join(*flCertDir, "device.pem")
	if remaining, ok := certTimeRemaining(certPath); ok && remaining > 30*24*time.Hour {
		logger.Info("existing certificate valid", "days_remaining", int(remaining.Hours()/24))
		return
	}

	if err := os.MkdirAll(*flCertDir, 0700); err != nil {
		logger.Error("creating cert directory", "error", err)
		os.Exit(1)
	}

	// Create attester.
	var att attester
	if *flSoftwareKey {
		att = &nullAttester{}
		logger.Info("using null attestation (dev/test mode)")
	} else {
		var err error
		att, err = newTPMAttester(logger, identifier)
		if err != nil {
			logger.Error("initializing TPM", "error", err)
			os.Exit(1)
		}
		logger.Info("using TPM 2.0 attestation")
	}
	defer att.close()

	// Generate ephemeral ACME account key and CSR key.
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Error("generating account key", "error", err)
		os.Exit(1)
	}
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Error("generating CSR key", "error", err)
		os.Exit(1)
	}

	// Run ACME enrollment.
	client := newACMEClient(logger, *flNanoCA, accountKey)
	certPEM, err := client.enroll(identifier, csrKey, att)
	if err != nil {
		logger.Error("enrollment failed", "error", err)
		os.Exit(1)
	}

	// Save certificate and private key.
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		logger.Error("writing certificate", "error", err)
		os.Exit(1)
	}
	keyPath := filepath.Join(*flCertDir, "device-key.pem")
	keyDER, _ := x509.MarshalECPrivateKey(csrKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		logger.Error("writing private key", "error", err)
		os.Exit(1)
	}

	// Install to nssdb for WARP mTLS.
	if err := installToNSSDB(*flNSSDB, identifier, certPath, keyPath); err != nil {
		logger.Warn("nssdb installation failed (may need nss-tools installed)", "error", err)
	}

	logger.Info("enrollment complete", "cert", certPath, "identifier", identifier)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func readDMISerial() (string, error) {
	data, err := os.ReadFile("/sys/class/dmi/id/product_serial")
	if err != nil {
		return "", fmt.Errorf("reading /sys/class/dmi/id/product_serial: %w", err)
	}
	s := strings.TrimSpace(string(data))
	if s == "" || s == "To Be Filled By O.E.M." || s == "Default string" {
		return "", fmt.Errorf("no valid DMI serial found: %q", s)
	}
	return s, nil
}

func certTimeRemaining(path string) (time.Duration, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return 0, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, false
	}
	return time.Until(cert.NotAfter), true
}

func installToNSSDB(nssdb, name, certPath, keyPath string) error {
	// Bundle cert + key into PKCS#12 for nssdb import.
	p12 := certPath + ".p12"
	out, err := exec.Command("openssl", "pkcs12", "-export",
		"-in", certPath, "-inkey", keyPath,
		"-out", p12, "-passout", "pass:", "-name", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pkcs12 export: %s: %w", out, err)
	}
	defer os.Remove(p12)

	out, err = exec.Command("pk12util", "-i", p12,
		"-d", "sql:"+nssdb, "-W", "").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pk12util import: %s: %w", out, err)
	}
	return nil
}
