// Package fleetauth implements a nanoca Authorizer that checks whether a
// device is enrolled in FleetDM before allowing certificate issuance.
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/freeish-project/nanoca"
)

// FleetAuthorizer checks Fleet's host inventory to authorize devices.
type FleetAuthorizer struct {
	fleetURL string
	apiToken string
	client   *http.Client
	logger   *slog.Logger
}

// New creates a Fleet authorizer. fleetURL is the Fleet server base URL
// (e.g., "https://fleet.example.com"). apiToken is a Fleet API token with
// host read permissions.
func New(logger *slog.Logger, fleetURL, apiToken string) *FleetAuthorizer {
	return &FleetAuthorizer{
		fleetURL: fleetURL,
		apiToken: apiToken,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// hostResponse is the Fleet response for GET /api/v1/fleet/hosts/identifier/:id.
// Fleet wraps the single matched host in a `host` field; we only need to know
// that the lookup succeeded plus the serial for logging.
type hostResponse struct {
	Host struct {
		HardwareSerial string `json:"hardware_serial"`
		UUID           string `json:"uuid"`
	} `json:"host"`
}

// Authorize checks whether the device's permanent identifier matches an
// enrolled host in Fleet. Returns true if Fleet returns a host for the
// identifier.
func (f *FleetAuthorizer) Authorize(ctx context.Context, device *nanoca.DeviceInfo) (bool, error) {
	if device == nil || device.PermanentIdentifier == nil || device.PermanentIdentifier.Identifier == "" {
		f.logger.WarnContext(ctx, "device has no permanent identifier, denying")
		return false, nil
	}

	identifier := device.PermanentIdentifier.Identifier
	f.logger.InfoContext(ctx, "checking Fleet enrollment", "identifier", identifier)

	found, serial, err := f.lookupHost(ctx, identifier)
	if err != nil {
		return false, fmt.Errorf("querying Fleet host: %w", err)
	}
	if !found {
		f.logger.WarnContext(ctx, "device not found in Fleet", "identifier", identifier)
		return false, nil
	}

	f.logger.InfoContext(ctx, "device authorized", "identifier", identifier, "matched_serial", serial)
	return true, nil
}

// lookupHost calls Fleet's /api/v1/fleet/hosts/identifier/:identifier endpoint
// which matches on hostname, osquery_host_identifier, node_key, UUID, or
// hardware_serial -- single exact match, no fuzzy pagination semantics.
func (f *FleetAuthorizer) lookupHost(ctx context.Context, identifier string) (bool, string, error) {
	endpoint := strings.TrimRight(f.fleetURL, "/") + "/api/v1/fleet/hosts/identifier/" + url.PathEscape(identifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Authorization", "Bearer "+f.apiToken)

	resp, err := f.client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("Fleet API request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var result hostResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return false, "", fmt.Errorf("decoding Fleet response: %w", err)
		}
		return true, result.Host.HardwareSerial, nil
	case http.StatusNotFound:
		return false, "", nil
	default:
		return false, "", fmt.Errorf("Fleet API returned %d", resp.StatusCode)
	}
}
