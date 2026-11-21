# ---- build ----
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/asi ./cmd/asi

# ---- runtime ----
FROM alpine:3.22
RUN apk add --no-cache nmap nmap-scripts ca-certificates tzdata \
 && adduser -D -H -h /data asi && mkdir -p /data && chown asi:asi /data
COPY --from=build /out/asi /usr/local/bin/asi
COPY docs /opt/asi/docs
COPY examples /opt/asi/examples
ENV ASI_LISTEN=0.0.0.0:7780 ASI_DATA_DIR=/data ASI_NMAP_PATH=/usr/bin/nmap
VOLUME /data
EXPOSE 7780
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s CMD ["asi", "healthcheck"]
# Runs as root inside the container so nmap can use raw sockets (NET_RAW is
# granted explicitly in docker-compose); set ASI_NMAP_PRIVILEGED=false and
# USER asi for TCP-connect-only scanning.
ENTRYPOINT ["asi"]
CMD ["serve"]
