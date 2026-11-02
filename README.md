<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Server-side WS-Federation relying party for Go. It accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

Version 0.1.0. License: MIT. Module `github.com/rcbj/wsfed-caep-go`, package `wsfed`. Publishing is not set up. `develop` and `main` are the same commit when this tree is published; nothing here creates a remote.

## Usage

```go
party, err := wsfed.FromFile("wsfed.json", nil)
request, err := party.Login(&wsfed.LoginOptions{RelayState: wsfed.String("/")})
who, err := party.HandleReply(wsfed.ReplyRequest{Method: "POST", URL: "/wsfed", Body: body}, []string{request.ID})
```

`RelayState` is a `*string` in this module; pass a pointer when the browser should return somewhere. JSON keys match the Node configuration: `realm`, `replyUrl`, `idpMetadata`, `privateKey`, `certificate`, `idpCa`, `idpEntityId`, `clockSkewSeconds`, `wantAssertionsEncrypted`, `allowUnsolicited`, `requestTokenType`, `signals`, `ssf`. `file:` and `env:` prefixes are accepted. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`.

`signals` omitted or `true` is on. The resolved configuration omits the key in that case (`SignalsSet` stays false). `false` is kept, does not start a receiver, and does not require transmitter metadata. Sign-in is unchanged either way: WS-Federation does not send OAuth scopes. Any other value raises a config error whose message is `signals must be true or false`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-go-demo \
  wsfed-caep generate-keys --config demo/wsfed.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-go-demo \
  wsfed-caep metadata --config demo/wsfed.json
```

The generated certificate's common name defaults to `wsfed-caep-nodejs relying party` plus the realm, cut at 64 characters.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

`go test` covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior, and the demo handler. No live iya-sts.

## Live sign-in

`python3 scripts/live_iya_sts.py` is the live half, on the host's Python. It starts a fresh iya-sts (main, memory mode, no persistence, no clustering) unless `IYA_STS_URL` is already set; `IYA_STS_IMAGE` starts one from an image you already have. It builds the demo image, runs `wsfed-caep generate-keys` inside it, and registers the demo with `python3 scripts/configure_iya_sts.py`, which uses only the standard library. The Go toolchain never runs on the host. The registrar trusts the self-signed root CA at the end of the chain iya-sts presents in the TLS handshake. The script signs in, emits credential-change, then session-revoked, and requires `GET /live-status` to show both. That JSON is `signedIn`, `subject`, `receiver`, and `events` of `type` and `jti`. It has no tokens. session-revoked leaves `signedIn` false. The last thing it prints is JSON with `"ok": true`.

```sh
python3 scripts/live_iya_sts.py
IYA_STS_IMAGE=iya-sts-live:main LIVE_STS_PORT=18521 LIVE_DEMO_PORT=18621 python3 scripts/live_iya_sts.py
```

The defaults are 18521 for iya-sts and 18621 for the demo. Do not bind host ports 3000, 8081, or 18481 to 18495. The containers are `iya-sts-live-wsfed-caep-go` and `wsfed-caep-go-live-demo`, and the script removes both.

iya-sts main sets the WS-Federation assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index finds nobody. The demo ends its one session from the event handler (`App.Remember` in `demo/app.go`), as the Java demo does in `Demo.java`.

[`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) runs `docker build --target test .` and then the live script at 07:22 UTC (`22 7 * * *`), and on `workflow_dispatch`. Push and pull-request CI stays in `tests.yml`.

## Layout

`wsfed/` library. `stubidp/` test identity provider. `demo/` HTTP handler. `cmd/wsfed-demo` and `cmd/wsfed-caep`. `scripts/configure_iya_sts.py` registers the demo with iya-sts; the container `PORT` wins over the shell `PORT`, and an explicit public URL wins over both. `scripts/live_iya_sts.py` is the live sign-in. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok` before the identity provider is dialed. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders and omits `signals`. Do not commit `demo/generated`.
