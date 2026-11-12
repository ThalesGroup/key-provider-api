# Key Provider API

## Disclaimer

THIS CODE IS FOR RESEARCH PURPOSES ONLY, AND SHOULD NOT IN ANY WAY BE USED IN PRODUCTION ENVIRONMENTS.

## Description

Stateless REST API that generates AES-128 cryptographic keys on demand.
Key material never travels in plaintext: both the request and the response
are **JWE JSON Serializations** ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516))
encrypted with a pre-shared **KEK** (Key Encryption Key), and generated keys
are returned as **JWK** ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517))
symmetric key objects sealed inside the JWE response.

The service stores nothing — every request produces a fresh, ephemeral key
from the OS CSPRNG. See `integration_api_readme.md` for the full protocol
spec and `integration_openapi.yaml` for the OpenAPI contract.

## Encryption scheme

| Item       | Value                                    |
|------------|------------------------------------------|
| Key wrap   | `A128KW` (AES Key Wrap, RFC 3394)        |
| Encryption | `A128GCM` (AES-128-GCM)                  |
| KEK size   | 128 bits (16 bytes), base64url-encoded   |
| Generated  | 128-bit AES key, base64url in JWK `k`    |

`A128KW` wraps a freshly generated Content Encryption Key (CEK) with the
pre-shared KEK; `A128GCM` encrypts the payload with the CEK. Requests use
`cty: application/json`, responses use `cty: jwk+json`.

## Endpoints

| Method | Path      | Request                | Response               |
|--------|-----------|------------------------|------------------------|
| `GET`  | `/`       | —                      | `application/json` API documentation |
| `GET`  | `/health` | — (no auth)            | `application/json` `{"status":"ok","version":"…"}` |
| `POST` | `/v1/keys`| `application/jose+json` JWE wrapping `{"use":"enc"|"sig","kid":"…"}` | `application/jose+json` JWE wrapping the JWK |

Errors return plain JSON with `error` (`invalid_request` → 400,
`decryption_failed` → 400, `internal_error` → 500), `message`, and a
`request_id` (UUID v4). Unknown paths return a JSON 404. Stderr logs only
method, path, status, and latency; each `POST /v1/keys` outcome is also
written to its own file in the working directory, numbered per request from
1 on each start (`1.log`, `2.log`, …), each containing one line, e.g.
`200: provided with fresh key XXXX` or `400: invalid KEK (…)` (files left by
a previous run are overwritten).
Note: these log files intentionally contain freshly generated keys —
protect them like key material.

## Code organization

```
src/
├── main.rs    — CLI (clap), AppState, request logic (process_keys_request),
│                 axum handlers + Router, #[tokio::main] entrypoint
├── crypto.rs  — JOSE primitives: JWE envelope type, base64url helpers,
│                 KEK loading, AES-KW (RFC 3394), AES-GCM, JWE encrypt/decrypt
└── tests.rs   — unit tests (crypto roundtrips, request logic, handlers)
```

`main.rs` owns HTTP and orchestration; `crypto.rs` owns all cryptography
and knows nothing about HTTP; `tests.rs` exercises both without a network
stack (handlers are called directly). The KEK is loaded once at startup
into `AppState` (served to handlers via axum `State`); if unset, the server
still starts but `POST /v1/keys` answers `500 internal_error`.

## Configuration

CLI flags take precedence over environment variables (which take precedence
over defaults):

| Flag          | Env          | Default     | Meaning                                      |
|---------------|--------------|-------------|----------------------------------------------|
| `--kek-value` | `KEK_VALUE`  | — (unset)   | KEK, base64url-encoded 16 bytes (`--kek`/`KEK` are aliases) |
| `--bind-addr` | `BIND_ADDR`  | —             | Full listen address, e.g. `127.0.0.1:3000` (overrides host/port) |
| `--host`      | `HOST`       | `0.0.0.0`   | Listen host (all interfaces by default)      |
| `--port`      | `PORT`       | `3000`      | Listen port                                  |

### Generating a new preshared key (KEK)

The KEK is 16 cryptographically random bytes, base64url-encoded **without
padding** (22 characters). Generate one from the Linux CSPRNG with standard
CLI tools:

```bash
# coreutils only: /dev/urandom -> base64 -> base64url, strip padding
head -c 16 /dev/urandom | base64 -w0 | tr '+/' '-_' | tr -d '='

# or with openssl:
openssl rand -base64 16 | tr -d '\n' | tr '+/' '-_' | tr -d '='
```

Example output:

```
WJC37HvPdvBEz6m-qcQB-Q
```

## Compile and run (native)

```bash
cargo build
cargo test            # 17 unit tests, no network needed
KEK_VALUE="AAECAwQFBgcICQoLDA0ODw" ./target/debug/key-provider-api
# or: ./target/debug/key-provider-api --kek-value AAECAwQFBgcICQoLDA0ODw --port 3000
curl -s http://127.0.0.1:3000/health
```

(`AAECAwQFBgcICQoLDA0ODw` is the base64url encoding of bytes `00..0f` —
a test vector, not a production secret.)

## Compile and run (wasm32-wasip2)

The `wasm32-wasip2` target needs tokio's unstable WASM networking support,
enabled repo-wide by `.cargo/config.toml`:

```toml
[target.wasm32-wasip2]
rustflags = ["--cfg", "tokio_unstable"]
```

Without that flag, tokio refuses its `net` feature on any wasm target
(hard `compile_error!`), which `axum::serve` + `tokio::net::TcpListener`
require. With it:

```bash
cargo build --target wasm32-wasip2
wasmtime run -S inherit-network=y -S tcp=y \
  --env KEK_VALUE="AAECAwQFBgcICQoLDA0ODw" --env PORT=3000 \
  target/wasm32-wasip2/debug/key-provider-api.wasm [--port 3000]
```

(When passing CLI args to the guest, place them directly after the `.wasm`
path, with no extra `--` separator.) The WASI build serves the same routes
with identical behavior; verify with the same `curl` commands as native.

## End-to-end tests

The `tests/` folder holds a commented end-to-end suite
(`tests/test_key_flow.py`) that exercises the full key flow against a
running server: health/docs probes, JWE request building (A128KW + A128GCM),
response decryption and JWK validation, key freshness, plus the error paths
(missing body, malformed JWE, wrong KEK, unknown route). Python dependencies
are managed with [uv](https://docs.astral.sh/uv/) via `tests/pyproject.toml`
(only `cryptography` beyond the standard library):

```bash
# 1. start the server with the same KEK the suite will use
KEK_VALUE="AAECAwQFBgcICQoLDA0ODw" ./target/debug/key-provider-api &

# 2. install the locked test environment and run the suite
cd tests
uv sync
uv run python test_key_flow.py            # defaults: 127.0.0.1:3000, test-vector KEK
uv run python test_key_flow.py --help     # --host/--port/--kek (or KP_HOST/KP_PORT/KEK_VALUE env)
```

Expected output:

```
target: http://127.0.0.1:3000
PASS GET /health
PASS GET / (docs)
PASS POST /v1/keys minimal
PASS POST /v1/keys kid+sig
PASS keys are fresh
PASS missing body -> 400
PASS malformed JWE -> 400
PASS wrong KEK -> 400
PASS unknown path -> 404
9/9 checks passed
```

The script exits non-zero on any failure and works unchanged against the
native binary and the `wasmtime`-hosted `wasm32-wasip2` build.
