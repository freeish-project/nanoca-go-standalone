// nanoca-server is a standalone ACME CA server wrapping the nanoca library.
// It serves ACME endpoints with device-attest-01 support for hardware-backed
// device identity via Apple Secure Enclave (macOS) and TPM 2.0 (Linux).
//
// Deployed as stateless replicas on Kubernetes with in-memory Badger storage.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"github.com/brandonweeks/nanoca/issuers/inprocess"
	"github.com/brandonweeks/nanoca/signers/file"
	"github.com/brandonweeks/nanoca/storage/badger"
	"github.com/brandonweeks/nanoca/verifiers/apple"
	"github.com/nfohs/nanoca-go-standalone/nanoca-server/fleetauth"
	"github.com/nfohs/nanoca-go-standalone/nanoca-server/tpmverifier"
)

func main() {
	var (
		flListen  = flag.String("listen", envOrDefault("NANOCA_LISTEN", ":8443"), "listen address")
		flCACert  = flag.String("ca-cert", envOrDefault("NANOCA_CA_CERT", "/etc/nanoca/ca.pem"), "CA certificate file")
		flCAKey   = flag.String("ca-key", envOrDefault("NANOCA_CA_KEY", "/etc/nanoca/ca.key"), "CA private key file")
		flBaseURL = flag.String("base-url", envOrDefault("NANOCA_BASE_URL", "https://ca.YOURDOMAIN.COM"), "external base URL for ACME directory")
		flPrefix  = flag.String("prefix", envOrDefault("NANOCA_PREFIX", "/acme"), "URL prefix for ACME endpoints")
		flDataDir  = flag.String("data-dir", envOrDefault("NANOCA_DATA_DIR", "/var/lib/nanoca"), "badger storage directory (empty for in-memory)")
		flEnableTPM  = flag.Bool("enable-tpm", envOrDefault("NANOCA_ENABLE_TPM", "") != "", "enable TPM 2.0 attestation verifier")
		flTPMRootsDir = flag.String("tpm-roots-dir", envOrDefault("NANOCA_TPM_ROOTS_DIR", "/var/lib/nanoca/tpm-roots"), "directory for cached TPM vendor root CAs")
		flFleetURL   = flag.String("fleet-url", envOrDefault("NANOCA_FLEET_URL", ""), "Fleet server URL for device authorization (empty = null authorizer)")
		flFleetToken = flag.String("fleet-token", envOrDefault("NANOCA_FLEET_TOKEN", ""), "Fleet API token for device authorization")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Load CA certificate
	certPEM, err := os.ReadFile(*flCACert)
	if err != nil {
		logger.Error("reading CA certificate", "error", err)
		os.Exit(1)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		logger.Error("no PEM block found in CA certificate file")
		os.Exit(1)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Error("parsing CA certificate", "error", err)
		os.Exit(1)
	}

	// Load CA signing key
	signer, err := file.LoadSigner(*flCAKey)
	if err != nil {
		logger.Error("loading CA key", "error", err)
		os.Exit(1)
	}

	// Configure storage
	var storageOpts badger.Options
	if *flDataDir != "" {
		storageOpts.Path = *flDataDir
		if err := os.MkdirAll(*flDataDir, 0700); err != nil {
			logger.Error("creating data dir", "error", err)
			os.Exit(1)
		}
	} else {
		storageOpts.InMemory = true
	}
	storage, err := badger.New(storageOpts)
	if err != nil {
		logger.Error("creating storage", "error", err)
		os.Exit(1)
	}

	// Create issuer (signs certs in-process using the CA cert + key)
	issuer := inprocess.New(caCert, signer)

	// Authorizer: use Fleet if configured, otherwise null (allow all).
	var authorizer nanoca.Authorizer
	if *flFleetURL != "" && *flFleetToken != "" {
		authorizer = fleetauth.New(logger, *flFleetURL, *flFleetToken)
		logger.Info("using Fleet authorizer", "fleet_url", *flFleetURL)
	} else {
		authorizer = nullauthorizer.New()
		logger.Info("using null authorizer (all devices allowed)")
	}

	// Verifiers: always register Apple; optionally register TPM.
	caOpts := []nanoca.Option{
		nanoca.WithPrefix(*flPrefix),
		nanoca.WithVerifier(apple.New(logger)),
	}

	if *flEnableTPM {
		// Fetch TPM vendor root CAs on startup.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		if err := tpmverifier.FetchRoots(ctx, logger, *flTPMRootsDir); err != nil {
			logger.Error("fetching TPM roots", "error", err)
			os.Exit(1)
		}
		cancel()

		// Start daily background refresh.
		stopRefresh := tpmverifier.StartPeriodicRefresh(logger, *flTPMRootsDir, 24*time.Hour)
		defer stopRefresh()

		caOpts = append(caOpts, nanoca.WithVerifier(tpmverifier.New(logger, *flTPMRootsDir)))
		logger.Info("TPM 2.0 verifier enabled", "roots_dir", *flTPMRootsDir)
	}

	// Create the CA
	ca, err := nanoca.New(
		logger,
		issuer,
		authorizer,
		storage,
		*flBaseURL,
		caOpts...,
	)
	if err != nil {
		logger.Error("creating CA", "error", err)
		os.Exit(1)
	}
	defer ca.Close()

	mux := http.NewServeMux()
	mux.Handle(*flPrefix+"/", ca.Handler())

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	logger.Info("listening", "addr", *flListen, "prefix", *flPrefix)
	if err := http.ListenAndServe(*flListen, mux); err != nil {
		logger.Error("server", "error", err)
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
