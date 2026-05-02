# nanoca-go-standalone

Standalone build of the [nanoca](https://github.com/brandonweeks/nanoca) ACME CA with Fleet device authorization, TPM 2.0 attestation, and Apple Secure Enclave attestation. Includes a `cloudflared`-fronted Kubernetes deployment.

Issues hardware-backed device identity certificates via ACME `device-attest-01`:
- **macOS**: Apple Secure Enclave attestation (Managed Device Attestation, fully OS-mediated)
- **Linux**: TPM 2.0 attestation via the bundled `fleet-acme-enroll` binary

## Deployment options

This binary is consumed two ways:

- **Cloudflare Containers (Freeish stack).** The [freeish](https://github.com/freeish-project/freeish) project clones this repo at a tagged version inside its own Dockerfile and runs the resulting image as a Cloudflare Container managed by a gateway Worker. The CA private key lives in a separate signing-oracle Worker (CF Secrets Store), and the binary uses `signers/remote` to delegate signing. See [HANDOFF_SECRETS_ADDENDUM.md](https://github.com/freeish-project/freeish/blob/main/HANDOFF_SECRETS_ADDENDUM.md) Part 2 for the full architecture; nothing in this repo needs to change to support that path.
- **Kubernetes (self-hosted).** Manifests in `k8s/`, with a `cloudflared` sidecar for Cloudflare Tunnel connectivity. The rest of this README covers the K8s path.

The CI workflow at `.github/workflows/build-push.yml` builds and pushes a multi-arch image to `ghcr.io/freeish-project/nanoca-server` on every push to `main`. Both deployment paths can pull from there, or build from source.

## Architecture (Kubernetes)

```
Managed Devices (macOS/Linux)
  -> Cloudflare WARP (encrypted tunnel + mTLS with device cert)
    -> Cloudflare Tunnel
      -> cloudflared sidecar (K8s pod)
        -> nanoca-server (localhost:8443)
          -> Fleet API (device authorization)
```

nanoca-server runs as stateless replicas with in-memory Badger storage. ACME state is ephemeral -- issued certs remain valid because the CA signing key persists in the K8s Secret. Pods can be rescheduled freely without data loss concerns.

The Fleet authorizer queries `/api/v1/fleet/hosts` to verify that requesting devices are enrolled before issuing certificates. Works for both macOS (serial number match) and Linux (UUID match). Available on both Fleet Free and Fleet Premium; no Premium-only endpoints are used.

## Prerequisites

- Kubernetes cluster
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) configured to route `ca.YOURDOMAIN.COM` to `localhost:8443`
- Fleet instance with API token (host read permissions)
- CA certificate and private key (generated offline)

## Quick Start

### 1. Generate CA keypair (offline, one-time)

The CA must be **ECDSA P-256 or P-384** if you plan to use the remote signing oracle (`signers/remote` rejects non-ECDSA keys at startup). ECDSA is also recommended on the K8s file-signer path so the same key works for either deployment.

```bash
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl pkcs8 -topk8 -nocrypt -out ca.key
openssl req -new -x509 -days 3650 -key ca.key -out ca.pem \
  -subj "/CN=YOURORG Device CA/O=YOURORG" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```

`ca.pem` is safe to distribute. Never commit `ca.key`.

### 2. Create K8s secrets

```bash
kubectl create namespace security-infra

kubectl -n security-infra create secret generic nanoca-secrets \
  --from-file=ca.pem=ca.pem \
  --from-file=ca.key=ca.key \
  --from-literal=NANOCA_FLEET_TOKEN=your-fleet-api-token \
  --from-literal=CLOUDFLARE_TUNNEL_TOKEN=your-tunnel-token
```

### 3. Update ConfigMap values

Edit `k8s/configmap.yaml` with your Fleet URL and base URL:
- `NANOCA_FLEET_URL`: Your Fleet server URL
- `NANOCA_BASE_URL`: The public URL for this nanoca instance (Cloudflare Tunnel hostname)

### 4. Apply manifests

```bash
kubectl apply -f k8s/
```

### 5. Configure Cloudflare Tunnel

In the Cloudflare Zero Trust dashboard, add a public hostname route:
- Hostname: `ca.YOURDOMAIN.COM`
- Service: `http://localhost:8443`

## macOS Enrollment

Deploy `profiles/acme-device-cert.mobileconfig` via Fleet MDM profiles.
Replace `YOURDOMAIN.COM`, `YOURORG`, and `GENERATE-UUID-HERE` with your values.

macOS handles the ACME flow automatically: Secure Enclave key generation,
device attestation via Apple's servers, and cert installation into the system keychain.

Requires macOS 14+, Apple Silicon or T2, and ADE/DEP supervised enrollment.

## Linux Enrollment

See [docs/linux-enrollment.md](docs/linux-enrollment.md) for building and deploying
the `fleet-acme-enroll` binary.

## Configuration Reference

| Environment Variable | Default | Description |
|---|---|---|
| `NANOCA_LISTEN` | `:8443` | Listen address |
| `NANOCA_CA_CERT` | `/etc/nanoca/ca.pem` | Path to CA certificate file |
| `NANOCA_CA_KEY` | `/etc/nanoca/ca.key` | Path to CA private key file (ignored if `NANOCA_REMOTE_SIGNER_URL` is set) |
| `NANOCA_BASE_URL` | `https://ca.YOURDOMAIN.COM` | External base URL for ACME directory |
| `NANOCA_PREFIX` | `/acme` | URL prefix for ACME endpoints |
| `NANOCA_DATA_DIR` | `/var/lib/nanoca` | Badger storage dir (empty = in-memory) |
| `NANOCA_CHAIN_FILE` | *(unset)* | Optional PEM file with intermediate/root chain certificates (RFC 8555 §7.4.2) |
| `NANOCA_REMOTE_SIGNER_URL` | *(unset)* | HTTP signing oracle URL. When set, replaces local CA key signing. ECDSA only. |
| `NANOCA_REMOTE_SIGNER_TOKEN` | *(unset)* | Bearer token for the signing oracle |
| `NANOCA_REMOTE_SIGNER_PUBKEY` | *(unset)* | Path to PKIX PEM public key for the oracle (used to verify returned signatures) |
| `NANOCA_ENABLE_TPM` | *(unset)* | Set to any value to enable TPM verifier |
| `NANOCA_TPM_ROOTS_DIR` | `/var/lib/nanoca/tpm-roots` | TPM vendor root CA cache directory |
| `NANOCA_FLEET_URL` | *(unset)* | Fleet server URL (empty = null authorizer) |
| `NANOCA_FLEET_TOKEN` | *(unset)* | Fleet API token |

## In-Memory Badger

Setting `NANOCA_DATA_DIR=""` enables in-memory Badger storage. This means:
- No PersistentVolumeClaim needed
- Replicas are fully stateless and interchangeable
- ACME nonces, orders, and account state are pod-local and ephemeral
- **Issued certificates remain valid** because the CA signing key persists in the K8s Secret independent of Badger state
- If a pod restarts mid-enrollment, the client retries from scratch (standard ACME behavior)

## Scaling

The HPA scales from 2 to 20 replicas based on CPU and memory utilization (70% target).
Each replica independently fetches TPM vendor root CAs on startup and refreshes daily.
