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

- Kubernetes cluster (1.25+ recommended; the manifests use stable APIs and do not require platform-specific extensions)
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) configured to route `ca.YOURDOMAIN.COM` to `localhost:8443`, or see [Deploying without Cloudflare Tunnel](#deploying-without-cloudflare-tunnel)
- Fleet instance with API token (host read permissions)
- CA certificate and private key (generated offline -- see step 1 below)

### Cluster requirements

- **metrics-server** must be running for the HPA to function. GKE has it enabled by default; EKS, AKS, and most vanilla clusters do not. Check with `kubectl top pod`.
- **Pod Security Standards.** The pod runs non-root, drops all capabilities, and uses the `RuntimeDefault` seccomp profile, so it satisfies the `baseline` profile out of the box. For namespaces enforcing `restricted`, additionally set `readOnlyRootFilesystem: true` on both containers (the cloudflared sidecar will need a writable `/tmp` mount added if you do).
- **Outbound egress.** The TPM verifier fetches vendor root CAs (Intel, AMD, NXP, etc.) on startup and refreshes them daily. A pod on a private cluster needs Cloud NAT or an egress proxy to reach those vendor URLs.
- **Cluster sizing.** A two-replica deployment requests roughly 1.2 vCPU and 1.3 GiB total (500m / 512Mi for nanoca-server plus 100m / 128Mi for the cloudflared sidecar, times two replicas). Plan accordingly on small clusters.
- **`secrets.yaml` is a template, not an apply target.** It contains base64 placeholders that would land in your cluster as literal `YOUR_*` strings. Use `kubectl create secret generic --from-file=...` (step 2 below) instead, or hand-edit the file before applying.
- **OpenShift.** The default `restricted-v2` SCC assigns a random non-root UID per namespace and rejects pods that pin `runAsUser`. To deploy on OpenShift, remove the `runAsUser: 65534` line from `deployment.yaml` (the binary works at any non-root UID since it only reads its mount paths) or grant the namespace's ServiceAccount a custom SCC.
- **Pin image tags for production.** The reference manifest uses `:latest` for both `nanoca-server` and `cloudflared`. Pin to a SHA or version tag in real deployments to avoid silent rollouts.

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

## Deploying without Cloudflare Tunnel

The default deployment uses a `cloudflared` sidecar so nanoca-server can listen on plain HTTP at `:8443` while Cloudflare's edge handles TLS termination, DDoS protection, and WAF in front of it. This is the simplest path and matches the architecture diagram above.

If you want to expose nanoca-server through a normal Kubernetes Ingress or Gateway instead -- for example, GKE Gateway, NGINX Ingress, or a cloud-managed Load Balancer -- two things to know:

- **nanoca-server speaks plain HTTP on its listen port.** The container does not terminate TLS itself; the port is named `https` in `service.yaml` only because the Cloudflare-fronted setup serves the public ACME directory over HTTPS. Your Ingress or LB must provide TLS termination.
- **Drop the cloudflared sidecar** from `deployment.yaml` and remove the `CLOUDFLARE_TUNNEL_TOKEN` line from `secrets.yaml`. The remaining nanoca-server container, ConfigMap, Service, HPA, and PDB are platform-agnostic.

ACME clients connecting from outside the cluster must reach the public hostname over HTTPS regardless of which path you choose -- the Apple `device-attest-01` flow on macOS will refuse non-HTTPS endpoints.

## Running with Docker

For development, testing, or single-host deployments, the same image runs as a plain `docker run`. The binary is a static Go binary; no K8s primitives are required.

```bash
# Generate ca.pem and ca.key per "Generate CA keypair" above first.
docker run -d --name nanoca \
  -p 8443:8443 \
  -v "$PWD/ca.pem:/etc/nanoca/ca.pem:ro" \
  -v "$PWD/ca.key:/etc/nanoca/ca.key:ro" \
  -e NANOCA_BASE_URL="https://ca.YOURDOMAIN.COM" \
  -e NANOCA_FLEET_URL="https://fleet.YOURDOMAIN.COM" \
  -e NANOCA_FLEET_TOKEN="$FLEET_TOKEN" \
  ghcr.io/freeish-project/nanoca-server:latest
```

The container listens on plain HTTP at `:8443`. Front it with a TLS-terminating reverse proxy (nginx, Caddy, Traefik) before exposing publicly -- the Apple `device-attest-01` flow requires HTTPS endpoints. For local development without TLS, set `NANOCA_BASE_URL="http://localhost:8443"`.

To run without Fleet authorization (dev/test only -- any device can request a cert), omit `NANOCA_FLEET_URL` and `NANOCA_FLEET_TOKEN`; the binary falls back to the null authorizer.

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
