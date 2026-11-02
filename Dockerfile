# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test .` runs the suite in this image.
# The demo image below does not run it.
# wsfed/trust_chain_test.go runs scripts/trust_chain.py and the install script
# with this image's python3 and openssl.
FROM golang:1.27-bookworm AS test
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Only what the build and the suite read, so a new trust chain in
# demo/generated does not retest anything.
COPY go.mod go.sum ./
COPY wsfed wsfed
COPY stubidp stubidp
COPY cmd cmd
COPY scripts scripts
COPY demo/app.go demo/app_test.go demo/wsfed.json demo/
COPY demo/public demo/public
RUN go test ./...

FROM golang:1.27-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY wsfed wsfed
COPY stubidp stubidp
COPY cmd cmd
# demo/app.go embeds demo/public/styles.css.
COPY demo/app.go demo/app.go
COPY demo/public demo/public
RUN go build -o /usr/local/bin/wsfed-demo ./cmd/wsfed-demo \
 && go build -o /usr/local/bin/wsfed-caep ./cmd/wsfed-caep
COPY scripts scripts
COPY README.md LICENSE VERSION ./
# demo/ comes after the build, so a new chain does not rebuild the binaries.
# .dockerignore admits one file of demo/generated: idp-ca.pem, the iya-sts
# listener CA trust chain scripts/configure_iya_sts.py writes where idpCa
# names it. When it exists, this COPY puts it at
# /app/demo/generated/idp-ca.pem and the image trusts that iya-sts with no
# bind mount and no fetch; rebuild after running the install script against
# a different iya-sts. When it does not (a fresh clone, CI), the build still
# succeeds: a COPY of the demo DIRECTORY always has a source, where naming the
# file or a glob that matches nothing fails in both builders. The key pair,
# the IdP metadata and any password never enter the image.
COPY demo demo
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" || exit 1
CMD ["wsfed-demo"]
