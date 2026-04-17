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

// hostsResponse is the minimal Fleet API response for /api/v1/fleet/hosts.
type hostsResponse struct {
	Hosts []host `json:"hosts"`
}

type host struct {
	HardwareSerial string `json:"hardware_serial"`
	UUID           string `json:"uuid"`
}

// Authorize checks whether the device's permanent identifier matches an
// enrolled host in Fleet. Returns true if a matching host is found.
func (f *FleetAuthorizer) Authorize(ctx context.Context, device *nanoca.DeviceInfo) (bool, error) {
	if device == nil || device.PermanentIdentifier == nil || device.PermanentIdentifier.Identifier == "" {
		f.logger.WarnContext(ctx, "device has no permanent identifier, denying")
		return false, nil
	}

	identifier := device.PermanentIdentifier.Identifier
	f.logger.InfoContext(ctx, "checking Fleet enrollment", "identifier", identifier)

	hosts, err := f.queryHosts(ctx, identifier)
	if err != nil {
		return false, fmt.Errorf("querying Fleet hosts: %w", err)
	}

	for _, h := range hosts {
		if h.HardwareSerial == identifier || h.UUID == identifier {
			f.logger.InfoContext(ctx, "device authorized", "identifier", identifier, "matched_serial", h.HardwareSerial)
			return true, nil
		}
	}

	f.logger.WarnContext(ctx, "device not found in Fleet", "identifier", identifier)
	return false, nil
}

func (f *FleetAuthorizer) queryHosts(ctx context.Context, query string) ([]host, error) {
	u, err := url.Parse(f.fleetURL + "/api/v1/fleet/hosts")
	if err != nil {
		return nil, fmt.Errorf("parsing Fleet URL: %w", err)
	}
	u.RawQuery = url.Values{"query": {query}}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+f.apiToken)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Fleet API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Fleet API returned %d", resp.StatusCode)
	}

	var result hostsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding Fleet response: %w", err)
	}

	return result.Hosts, nil
}
