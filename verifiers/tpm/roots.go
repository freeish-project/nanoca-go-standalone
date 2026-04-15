package tpm

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// vendorRoot describes a TPM manufacturer root CA certificate to fetch.
type vendorRoot struct {
	Name string // filename-safe name (e.g., "intel-ek-root")
	URL  string // official PKI endpoint (DER or PEM)
}

// vendorRoots lists root CAs fetched directly from manufacturer PKI endpoints.
// Each URL points to the vendor's official certificate distribution point.
var vendorRoots = []vendorRoot{
	// Intel
	{Name: "intel-ek-root", URL: "https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer"},

	// AMD
	{Name: "amd-tpm-rsa-root", URL: "https://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121"},
	{Name: "amd-tpm-ecc-root", URL: "https://ftpm.amd.com/pki/aia/23452201D41C5AB064032BD23F158FEF"},

	// Infineon OPTIGA
	{Name: "infineon-optiga-rsa-root-1", URL: "https://pki.infineon.com/OptigaRsaRootCA/OptigaRsaRootCA.crt"},
	{Name: "infineon-optiga-rsa-root-2", URL: "https://pki.infineon.com/OptigaRsaRootCA2/OptigaRsaRootCA2.crt"},
	{Name: "infineon-optiga-rsa-root-3", URL: "https://pki.infineon.com/OptigaRsaRootCA3/OptigaRsaRootCA3.crt"},
	{Name: "infineon-optiga-ecc-root-1", URL: "https://pki.infineon.com/OptigaEccRootCA/OptigaEccRootCA.crt"},
	{Name: "infineon-optiga-ecc-root-2", URL: "https://pki.infineon.com/OptigaEccRootCA2/OptigaEccRootCA2.crt"},
	{Name: "infineon-optiga-ecc-root-3", URL: "https://pki.infineon.com/OptigaEccRootCA3/OptigaEccRootCA3.crt"},

	// STMicroelectronics (via GlobalSign)
	{Name: "globalsign-tpm-rsa-root", URL: "https://secure.globalsign.com/cacert/gstpmroot.crt"},
	{Name: "globalsign-tpm-ecc-root", URL: "https://secure.globalsign.com/cacert/tpmeccroot.crt"},
	{Name: "stmicro-stsafe-ecc-root-02", URL: "https://sw-center.st.com/STSAFE/STSAFEEccRootCA02.crt"},
	{Name: "stmicro-stsafe-rsa-root-02", URL: "https://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt"},

	// Nuvoton (common chip families)
	{Name: "nuvoton-ntc-ek-root-01", URL: "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/NTC%20TPM%20EK%20Root%20CA%2001.cer"},
	{Name: "nuvoton-ntc-ek-root-02", URL: "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/NTC%20TPM%20EK%20Root%20CA%2002.cer"},

	// Microsoft
	{Name: "microsoft-tpm-root-2014", URL: "https://www.microsoft.com/pkiops/certs/Microsoft%20TPM%20Root%20Certificate%20Authority%202014.crt"},
}

// FetchRoots downloads TPM vendor root CA certificates from official PKI
// endpoints and writes them as PEM files to dir. Existing files are
// overwritten on success. Failed downloads are logged but do not cause an
// error -- cached roots from a previous fetch remain usable.
func FetchRoots(ctx context.Context, logger *slog.Logger, dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating roots dir: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	var fetched, failed int

	for _, root := range vendorRoots {
		if err := fetchAndWrite(ctx, client, root, dir); err != nil {
			logger.Warn("failed to fetch TPM root CA", "name", root.Name, "url", root.URL, "error", err)
			failed++
			continue
		}
		fetched++
	}

	logger.Info("TPM root CA fetch complete", "fetched", fetched, "failed", failed, "dir", dir)
	return nil
}

func fetchAndWrite(ctx context.Context, client *http.Client, root vendorRoot, dir string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, root.URL, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB limit per cert
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	// Detect format: if it starts with "-----BEGIN", it's already PEM.
	// Otherwise treat as DER and convert to PEM.
	var pemBytes []byte
	if strings.HasPrefix(string(body), "-----BEGIN") {
		pemBytes = body
	} else {
		// Validate it's a parseable certificate before writing.
		if _, err := x509.ParseCertificate(body); err != nil {
			return fmt.Errorf("invalid DER certificate: %w", err)
		}
		pemBytes = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: body,
		})
	}

	outPath := filepath.Join(dir, root.Name+".pem")
	if err := os.WriteFile(outPath, pemBytes, 0600); err != nil {
		return fmt.Errorf("writing PEM: %w", err)
	}

	return nil
}

// LoadRootsFromDir reads all PEM files in dir and returns a cert pool and
// a count of loaded certificates. Returns an empty pool (not nil) if dir
// doesn't exist or contains no valid certs.
func LoadRootsFromDir(dir string) (*x509.CertPool, int, error) {
	pool := x509.NewCertPool()
	count := 0

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return pool, 0, nil
		}
		return nil, 0, fmt.Errorf("reading roots dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		if pool.AppendCertsFromPEM(data) {
			count++
		}
	}

	return pool, count, nil
}

// StartPeriodicRefresh launches a background goroutine that re-fetches TPM
// root CAs at the given interval. Returns a function to stop the refresh.
func StartPeriodicRefresh(logger *slog.Logger, dir string, interval time.Duration) (stop func()) {
	var once sync.Once
	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				FetchRoots(ctx, logger, dir)
				cancel()
			case <-done:
				return
			}
		}
	}()

	return func() { once.Do(func() { close(done) }) }
}
