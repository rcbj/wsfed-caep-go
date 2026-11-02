# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
FROM golang:1.27-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /usr/local/bin/wsfed-demo ./cmd/wsfed-demo
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" || exit 1
CMD ["wsfed-demo"]
