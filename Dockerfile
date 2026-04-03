# nanoca-server -- standalone ACME CA for Kubernetes
# CA cert/key are NOT baked in; they come from a K8s Secret volume mount.
# Cloudflared is NOT included; it runs as a separate sidecar container.

FROM golang:1.22-alpine AS build
RUN apk add --no-cache git
WORKDIR /build/nanoca-server
COPY nanoca-server/ .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /nanoca-server .
WORKDIR /build/fleet-acme-enroll
COPY fleet-acme-enroll/ .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /fleet-acme-enroll .

FROM alpine:latest
RUN apk add --no-cache ca-certificates curl
RUN adduser -D -u 65534 nanoca
COPY --from=build /nanoca-server /usr/local/bin/nanoca-server
COPY --from=build /fleet-acme-enroll /usr/local/bin/fleet-acme-enroll
RUN mkdir -p /var/lib/nanoca /etc/nanoca && chown -R nanoca:nanoca /var/lib/nanoca
USER nanoca
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8443/health || exit 1
ENTRYPOINT ["nanoca-server"]
