#!/usr/bin/env python3
"""End-to-end tests for the key-provider-api key generation flow.

The server under test must already be running with the SAME preshared KEK
this script uses (see --kek / KEK_VALUE), e.g.::

    KEK_VALUE="AAECAwQFBgcICQoLDA0ODw" ./target/debug/key-provider-api &
    cd tests && uv sync && uv run python test_key_flow.py

What is covered:
  1. Liveness probe (GET /health) and API docs (GET /).
  2. Full key flow: build a JWE request (A128KW + A128GCM) -> POST /v1/keys
     -> decrypt the JWE response -> validate the returned JWK.
  3. Freshness: two consecutive keys must differ.
  4. Error paths: missing body, malformed JWE, wrong KEK, unknown route.

Exit status is 0 only if every check passes.
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

# Default test KEK: base64url of bytes 0x00..0x0f. A *test vector* — never a
# production secret. Must match the server's configured KEK.
DEFAULT_KEK_B64 = "AAECAwQFBgcICQoLDA0ODw"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def b64u_encode(raw: bytes) -> str:
    """base64url-encode without padding (JOSE style)."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(s: str) -> bytes:
    """Decode unpadded base64url, tolerating the missing padding."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def http_get(base_url: str, path: str):
    """GET path; returns (status, content_type, parsed_json)."""
    with urllib.request.urlopen(base_url + path, timeout=5) as resp:
        return resp.status, resp.headers.get_content_type(), json.loads(resp.read())


def http_post_jwe(base_url: str, payload: dict | bytes) -> tuple[int, str, dict]:
    """POST a JSON body to /v1/keys; returns (status, content_type, body).

    Raises urllib.error.HTTPError on 4xx/5xx so error-path tests can
    inspect the status code and the JSON error envelope.
    """
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    req = urllib.request.Request(
        base_url + "/v1/keys",
        data=data,
        headers={"Content-Type": "application/jose+json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, resp.headers.get_content_type(), json.loads(resp.read())


# ---------------------------------------------------------------------------
# JWE client (mirrors the server's A128KW + A128GCM scheme)
# ---------------------------------------------------------------------------

def build_request_jwe(kek: bytes, params: dict) -> dict:
    """Wrap ``params`` (e.g. {"use": "enc"}) in a JWE JSON Serialization."""
    cek = os.urandom(16)  # fresh Content Encryption Key per request
    iv = os.urandom(12)  # fresh 96-bit IV per request (never reuse with same key)
    protected = json.dumps(
        {"alg": "A128KW", "enc": "A128GCM", "cty": "application/json"},
        separators=(",", ":"),
    )
    protected_b64 = b64u_encode(protected.encode())
    # AESGCM.encrypt() returns ciphertext || 16-byte auth tag; the JWE
    # envelope carries them as separate `ciphertext` / `tag` fields.
    sealed = AESGCM(cek).encrypt(iv, json.dumps(params).encode(), protected_b64.encode())
    return {
        "protected": protected_b64,
        "encrypted_key": b64u_encode(aes_key_wrap(kek, cek)),
        "iv": b64u_encode(iv),
        "ciphertext": b64u_encode(sealed[:-16]),
        "tag": b64u_encode(sealed[-16:]),
    }


def decrypt_response_jwe(kek: bytes, jwe: dict) -> dict:
    """Unwrap + decrypt a response JWE; returns the JWK as a dict."""
    protected_b64 = jwe["protected"]
    protected = json.loads(b64u_decode(protected_b64))
    assert protected["alg"] == "A128KW", f"unexpected alg: {protected}"
    assert protected["enc"] == "A128GCM", f"unexpected enc: {protected}"
    assert protected["cty"] == "jwk+json", f"unexpected cty: {protected}"
    cek = aes_key_unwrap(kek, b64u_decode(jwe["encrypted_key"]))
    plaintext = AESGCM(cek).decrypt(
        b64u_decode(jwe["iv"]),
        b64u_decode(jwe["ciphertext"]) + b64u_decode(jwe["tag"]),
        protected_b64.encode(),  # AAD is the encoded protected header
    )
    return json.loads(plaintext)


def assert_valid_jwk(jwk: dict, *, use: str, kid: str | None = None) -> None:
    """Validate the shape of a generated AES-128 JWK."""
    assert jwk["kty"] == "oct", jwk
    assert jwk["alg"] == "A128GCM", jwk
    assert jwk["use"] == use, jwk
    assert len(b64u_decode(jwk["k"])) == 16, "JWK 'k' must decode to 16 bytes"
    if kid is None:
        UUID(jwk["kid"])  # server-generated kid must be a UUID
    else:
        assert jwk["kid"] == kid, jwk


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------

def test_health(base_url: str) -> None:
    status, ctype, body = http_get(base_url, "/health")
    assert status == 200, status
    assert ctype == "application/json", ctype
    assert body["status"] == "ok", body
    assert body.get("version"), body


def test_docs(base_url: str) -> None:
    status, _, body = http_get(base_url, "/")
    assert status == 200, status
    assert body["name"] == "key-provider-api", body
    assert body.get("endpoints"), body


def test_generate_default(base_url: str, kek: bytes) -> None:
    """Minimal flow: {"use": "enc"} -> 200 JWE -> valid JWK."""
    status, ctype, resp_jwe = http_post_jwe(
        base_url, build_request_jwe(kek, {"use": "enc"})
    )
    assert status == 200, status
    assert ctype == "application/jose+json", ctype
    assert_valid_jwk(decrypt_response_jwe(kek, resp_jwe), use="enc")


def test_generate_with_kid_and_sig(base_url: str, kek: bytes) -> None:
    """Client-supplied kid + use=sig must be echoed in the JWK."""
    kid = "e2e-service-key-001"
    _, _, resp_jwe = http_post_jwe(
        base_url, build_request_jwe(kek, {"use": "sig", "kid": kid})
    )
    assert_valid_jwk(decrypt_response_jwe(kek, resp_jwe), use="sig", kid=kid)


def test_keys_are_fresh(base_url: str, kek: bytes) -> None:
    """The service is stateless: two requests must yield different keys."""
    _, _, first = http_post_jwe(base_url, build_request_jwe(kek, {"use": "enc"}))
    _, _, second = http_post_jwe(base_url, build_request_jwe(kek, {"use": "enc"}))
    k1 = decrypt_response_jwe(kek, first)["k"]
    k2 = decrypt_response_jwe(kek, second)["k"]
    assert k1 != k2, "two consecutive keys must differ"


def read_http_error(err: urllib.error.HTTPError) -> tuple[int, dict]:
    """Parse the JSON error envelope from an HTTPError."""
    return err.code, json.loads(err.read())


def test_missing_body(base_url: str) -> None:
    req = urllib.request.Request(
        base_url + "/v1/keys", data=b"", headers={"Content-Type": "application/jose+json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as err:
        status, body = read_http_error(err)
        assert status == 400, status
        assert body["error"] == "invalid_request", body
        assert body.get("request_id"), body
        return
    raise AssertionError("empty body unexpectedly accepted")


def test_malformed_jwe(base_url: str) -> None:
    try:
        http_post_jwe(base_url, b"not-json{{{")
    except urllib.error.HTTPError as err:
        status, body = read_http_error(err)
        assert status == 400, status
        assert body["error"] == "invalid_request", body
        return
    raise AssertionError("malformed JWE unexpectedly accepted")


def test_wrong_kek(base_url: str, kek: bytes) -> None:
    """A request wrapped under a different KEK must fail closed (400)."""
    other_kek = bytes((b + 1) % 256 for b in kek)
    try:
        http_post_jwe(base_url, build_request_jwe(other_kek, {"use": "enc"}))
    except urllib.error.HTTPError as err:
        status, body = read_http_error(err)
        assert status == 400, status
        assert body["error"] == "decryption_failed", body
        return
    raise AssertionError("wrong-KEK request unexpectedly accepted")


def test_unknown_path(base_url: str) -> None:
    try:
        http_get(base_url, "/no-such-route")
    except urllib.error.HTTPError as err:
        status, body = read_http_error(err)
        assert status == 404, status
        assert body["error"] == "invalid_request", body
        return
    raise AssertionError("unknown path unexpectedly accepted")


CHECKS = [
    ("GET /health", lambda ctx: test_health(ctx["base_url"])),
    ("GET / (docs)", lambda ctx: test_docs(ctx["base_url"])),
    ("POST /v1/keys minimal", lambda ctx: test_generate_default(ctx["base_url"], ctx["kek"])),
    ("POST /v1/keys kid+sig", lambda ctx: test_generate_with_kid_and_sig(ctx["base_url"], ctx["kek"])),
    ("keys are fresh", lambda ctx: test_keys_are_fresh(ctx["base_url"], ctx["kek"])),
    ("missing body -> 400", lambda ctx: test_missing_body(ctx["base_url"])),
    ("malformed JWE -> 400", lambda ctx: test_malformed_jwe(ctx["base_url"])),
    ("wrong KEK -> 400", lambda ctx: test_wrong_kek(ctx["base_url"], ctx["kek"])),
    ("unknown path -> 404", lambda ctx: test_unknown_path(ctx["base_url"])),
]


# ---------------------------------------------------------------------------
# CLI + runner
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="End-to-end tests for key-provider-api (server must be running)."
    )
    parser.add_argument("--host", default=os.environ.get("KP_HOST", "127.0.0.1"))
    parser.add_argument("--port", default=os.environ.get("KP_PORT", "3000"))
    parser.add_argument(
        "--kek",
        default=os.environ.get("KEK_VALUE", os.environ.get("KEK", DEFAULT_KEK_B64)),
        help="preshared KEK, base64url (default: env KEK_VALUE/KEK or test vector)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ctx = {
        "base_url": f"http://{args.host}:{args.port}",
        "kek": b64u_decode(args.kek),
    }
    if len(ctx["kek"]) != 16:
        print(f"error: KEK must decode to 16 bytes, got {len(ctx['kek'])}", file=sys.stderr)
        return 2
    print(f"target: {ctx['base_url']}")

    failed = 0
    for name, check in CHECKS:
        try:
            check(ctx)
        except urllib.error.HTTPError as err:
            # NOTE: HTTPError subclasses URLError, so it must be caught
            # first; here it means a *positive* check got an error status.
            try:
                detail = err.read().decode()
            except Exception:  # noqa: BLE001 - body may be unreadable
                detail = "<unreadable body>"
            print(f"FAIL {name}: unexpected HTTP {err.code}: {detail}")
            failed += 1
        except urllib.error.URLError as err:
            print(f"FAIL {name}: cannot reach server ({err}). Is it running?")
            failed += 1
        except AssertionError as err:
            print(f"FAIL {name}: {err}")
            failed += 1
        except Exception as err:  # noqa: BLE001 - surface unexpected errors plainly
            print(f"ERROR {name}: {type(err).__name__}: {err}")
            failed += 1
        else:
            print(f"PASS {name}")

    print(f"{len(CHECKS) - failed}/{len(CHECKS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
