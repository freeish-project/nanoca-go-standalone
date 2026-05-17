# nanoca-server -- standalone ACME CA for Kubernetes
# CA cert/key are NOT baked in; they come from a K8s Secret volume mount.
# Cloudflared is NOT included; it runs as a separate sidecar container.
# fleet-acme-enroll is the Linux endpoint client and ships as a separate
# release artifact, not in this server image.

FROM golang:1.26-alpine AS build
RUN apk add --no-cache git
WORKDIR /build
COPY go.mod go.sum ./
COPY authorizers/ authorizers/
COPY verifiers/ verifiers/
COPY cmd/ cmd/
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /nanoca-server ./cmd/nanoca-server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
RUN adduser -D -u 65534 nanoca
COPY --from=build /nanoca-server /usr/local/bin/nanoca-server
RUN mkdir -p /var/lib/nanoca /etc/nanoca && chown -R nanoca:nanoca /var/lib/nanoca
USER nanoca
EXPOSE 8443
# No HEALTHCHECK: Kubernetes startup/liveness/readiness probes own this. The
# directive only fires under plain Docker and previously forced a curl install.
ENTRYPOINT ["nanoca-server"]
