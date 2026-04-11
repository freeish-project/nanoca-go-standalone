# nanoca-go-standalone

## Project Overview

Standalone Kubernetes deployment of nanoca ACME CA with Fleet Premium integration.
Issues device identity certificates via ACME device-attest-01 for macOS (Secure Enclave)
and Linux (TPM 2.0). Runs behind Cloudflare WARP/Tunnel.

Separate from the [freeish](https://github.com/nfohs/freeish) repo. The nanoca-server
Go source was forked from freeish's `nanoca/nanoca-server/` with an updated module path.

Uses `github.com/nfohs/nanoca` fork (branch `feat/chain-and-remote-signer`) via `replace`
directive in go.mod, pending upstream merge at `github.com/brandonweeks/nanoca`.

## Architecture

- **nanoca-server**: Go binary wrapping the nanoca library. Serves ACME endpoints.
- **fleet-acme-enroll**: Linux enrollment client. ACME device-attest-01 via TPM 2.0. Installs cert to nssdb for WARP mTLS.
- **cloudflared sidecar**: Runs in the same K8s pod. Routes Cloudflare Tunnel traffic to localhost:8443.
- **In-memory Badger**: Stateless replicas, no PVC needed. CA key persists in K8s Secret.
- **Fleet authorizer**: Queries Fleet Premium `/api/v1/fleet/hosts` to authorize enrollment.
- **TPM verifier**: Validates AIK cert chains against vendor root CAs. Fetches roots on startup, refreshes daily.
- **Apple verifier**: Built into nanoca library. Validates Secure Enclave attestation.
- **Certificate chain**: Optional intermediate/root chain served in ACME cert responses per RFC 8555 Section 7.4.2.
- **Remote signing oracle**: Optional HTTP signing oracle (`signers/remote`) for HSM/KMS backends. CA key stays off-box.

## Key Files

```
Dockerfile                              # Multi-stage build for both binaries
nanoca-server/                          # Go source (ACME CA server)
  main.go                              # Server entry point, flag/env config
  fleetauth/fleetauth.go               # Fleet Premium host inventory authorizer
  tpmverifier/tpmverifier.go           # TPM 2.0 attestation verifier
  tpmverifier/roots.go                 # Vendor root CA fetcher + periodic refresh
fleet-acme-enroll/                      # Go source (Linux enrollment client)
  main.go                              # CLI entry, DMI serial detection, nssdb install
  acme.go                              # ACME client with JWS signing (go-jose)
  attest.go                            # TPM attestation + null attester (dev/test)
k8s/                                   # Kubernetes manifests
  namespace.yaml                       # security-infra namespace
  deployment.yaml                      # nanoca-server + cloudflared sidecar
  service.yaml                         # ClusterIP service
  configmap.yaml                       # Non-secret configuration
  secrets.yaml                         # CA cert/key, Fleet token, tunnel token
  hpa.yaml                             # HorizontalPodAutoscaler (2-20 replicas)
  pdb.yaml                             # PodDisruptionBudget (minAvailable: 1)
profiles/acme-device-cert.mobileconfig # macOS ACME enrollment profile
docs/linux-enrollment.md               # Linux fleet-acme-enroll deployment guide
.github/workflows/build-push.yml       # CI/CD: build + push to GHCR
```

## Commands

```bash
# Build image locally
docker build -t nanoca-server .

# Deploy to K8s
kubectl apply -f k8s/

# View logs
kubectl -n security-infra logs -l app=nanoca-server -c nanoca-server

# Run tests
cd nanoca-server && go test ./...
```

## Conventions

- All deployer-specific values use placeholders: `YOURDOMAIN.COM`, `YOURORG`, `YOUR_*`
- CA private key NEVER committed to git (enforced by .gitignore)
- nanoca-server configured entirely via environment variables (with flag fallbacks)
- K8s Secret mounted as files at `/etc/nanoca/` for CA cert/key (not env vars)
- `NANOCA_CA_CERT` and `NANOCA_CA_KEY` env vars are **file paths**, not cert content
- `NANOCA_CHAIN_FILE` is an optional PEM file path for intermediate/root chain certificates
- Remote signer configured via `NANOCA_REMOTE_SIGNER_URL`, `NANOCA_REMOTE_SIGNER_TOKEN`, `NANOCA_REMOTE_SIGNER_PUBKEY` (replaces `NANOCA_CA_KEY`)

## Security

- Pod runs as non-root (uid 65534)
- CA key file mounted read-only with mode 0400
- Fleet API token injected as env var from Secret (not mounted as file)
- Cloudflare Tunnel token injected as env var from Secret

## Fleet Premium API Compatibility

The Fleet authorizer uses `/api/v1/fleet/hosts?query=<identifier>` with Bearer token auth.
This endpoint is available in both Fleet Free and Fleet Premium. The authorizer matches on
`hardware_serial` (macOS) or `uuid` (Linux). No Fleet Premium-specific endpoints are used.
