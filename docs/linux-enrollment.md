# Linux Device Enrollment

Linux devices require the `fleet-acme-enroll` binary to obtain device identity
certificates from nanoca. Unlike macOS (which has a built-in ACME client),
Linux uses TPM 2.0 attestation via the `device-attest-01` ACME challenge type.

## Prerequisites

- TPM 2.0 available on the device
- `nss-tools` installed (for WARP mTLS nssdb import)
- Device enrolled in Fleet Premium

## Building fleet-acme-enroll

The binary source lives in this repo at `fleet-acme-enroll/`.

```bash
cd nanoca/fleet-acme-enroll
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fleet-acme-enroll .
```

## Deploying via Fleet Premium

### Option A: Fleet Software Package

1. Package `fleet-acme-enroll` as a `.deb`:

```bash
# Create package structure
mkdir -p fleet-acme-enroll-pkg/usr/local/bin
mkdir -p fleet-acme-enroll-pkg/DEBIAN
cp fleet-acme-enroll fleet-acme-enroll-pkg/usr/local/bin/
chmod 755 fleet-acme-enroll-pkg/usr/local/bin/fleet-acme-enroll

cat > fleet-acme-enroll-pkg/DEBIAN/control << 'EOF'
Package: fleet-acme-enroll
Version: 1.0.0
Architecture: amd64
Maintainer: YOURORG <security@YOURDOMAIN.COM>
Description: ACME device-attest-01 enrollment client for nanoca
Depends: libtss2-esys-3.0.2-0, nss-tools
EOF

dpkg-deb --build fleet-acme-enroll-pkg fleet-acme-enroll_1.0.0_amd64.deb
```

2. Upload to Fleet Premium via UI: **Software > Add software > Upload**

3. Configure install script in Fleet:

```bash
dpkg -i fleet-acme-enroll_1.0.0_amd64.deb
fleet-acme-enroll \
  --nanoca-url https://ca.YOURDOMAIN.COM/acme \
  --cert-dir /etc/ssl/fleet-device \
  --nssdb /etc/pki/nssdb
```

### Option B: Fleet Setup Experience Script

For automatic enrollment during fleet device setup:

```bash
#!/bin/bash
set -euo pipefail

NANOCA_URL="https://ca.YOURDOMAIN.COM/acme"
CERT_DIR="/etc/ssl/fleet-device"
NSSDB="/etc/pki/nssdb"

# Download and run enrollment
curl -fsSL https://artifacts.YOURDOMAIN.COM/fleet-acme-enroll -o /tmp/fleet-acme-enroll
chmod +x /tmp/fleet-acme-enroll
/tmp/fleet-acme-enroll \
  --nanoca-url "$NANOCA_URL" \
  --cert-dir "$CERT_DIR" \
  --nssdb "$NSSDB"
rm /tmp/fleet-acme-enroll
```

## How It Works

1. `fleet-acme-enroll` auto-detects the device DMI serial number
2. Creates an ACME account with the nanoca server
3. Requests a certificate order
4. Responds to `device-attest-01` challenge with TPM attestation:
   - EK certs in x5c chain
   - TPM quote signed by AK with SHA256(challenge token) as nonce
   - DMI serial in attStmt
5. nanoca verifies TPM attestation against vendor root CAs
6. nanoca queries Fleet Premium to confirm device is enrolled
7. Certificate is issued, saved to `--cert-dir`, and imported to nssdb

## Known Limitations

- The x5c chain contains EK certs but the quote is signed by the AK. This
  works on TPMs with IAK certs; others may require verifier credential
  activation support.
- CSR key is currently software-based. A future iteration should use
  TPM-bound keys via PKCS#11.

## Renewal

Run `fleet-acme-enroll` again. If the existing cert has >30 days validity,
it skips re-enrollment. Set up a cron job or systemd timer:

```bash
# /etc/cron.daily/fleet-acme-enroll
#!/bin/bash
/usr/local/bin/fleet-acme-enroll \
  --nanoca-url https://ca.YOURDOMAIN.COM/acme \
  --cert-dir /etc/ssl/fleet-device \
  --nssdb /etc/pki/nssdb
```
