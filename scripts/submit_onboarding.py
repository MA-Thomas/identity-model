#!/usr/bin/env python3
"""Submit a composed FEN identity-onboarding request using a REAL device App
Attest assertion exported from the FenAppAttestProof iOS app.

Flow (mirrors the runtime-server E2E harness, but with a real registered-key
assertion instead of a static one):

  1. POST /mobile/identity-onboarding/live-presence-callback   (maps liveness evidence)
  2. POST /mobile/identity-onboarding                          (verifies the real assertion)

The App Attest assertion is bound to a single-use, time-limited live-presence
challenge nonce, so run this PROMPTLY after tapping "Copy Onboarding Inputs" in
the app (before the challenge expires).

Inputs
------
Onboarding inputs JSON (from the app's "Copy Onboarding Inputs" button). Provide
it one of three ways, in priority order:
  * --inputs-file PATH
  * piped on stdin
  * the macOS clipboard (pbpaste)

Environment (the backend must be running in apple_assertion mode with a matching
config; see REPRODUCE_IOS_APP_ATTEST_PROOF.md):
  IDENTITY_MODEL_KEYCLOAK_TOKEN         fresh Keycloak access token (required)
  IDENTITY_MODEL_KEYCLOAK_ISSUER        e.g. http://127.0.0.1:8080/realms/fen-dev (required)
  IDENTITY_MODEL_KEYCLOAK_CLIENT_ID     e.g. fen-identity-dev (required)
  IDENTITY_MODEL_LIVENESS_EXPECTED_ASSERTION
                                        must equal the backend's configured value
                                        (default: valid-live-presence)

Usage
-----
  python3 scripts/submit_onboarding.py --inputs-file inputs.json
  pbpaste | python3 scripts/submit_onboarding.py
  python3 scripts/submit_onboarding.py            # reads the clipboard
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import uuid

CALLBACK_PATH = "/mobile/identity-onboarding/live-presence-callback"
ONBOARDING_PATH = "/mobile/identity-onboarding"


def post_json(base_url, path, body):
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", "replace")
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, {"raw": raw}
    except urllib.error.URLError as error:
        sys.exit(f"Could not reach {base_url}{path}: {error}. Is the backend running?")


def read_inputs(args):
    if args.inputs_file:
        with open(args.inputs_file) as handle:
            return json.load(handle)
    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        if piped:
            return json.loads(piped)
    try:
        import subprocess

        clipboard = subprocess.run(
            ["pbpaste"], capture_output=True, text=True, check=False
        ).stdout.strip()
    except FileNotFoundError:
        clipboard = ""
    if not clipboard:
        sys.exit(
            "No onboarding inputs found. Tap 'Copy Onboarding Inputs' in the app, then "
            "re-run; or pass --inputs-file, or pipe the JSON on stdin."
        )
    return json.loads(clipboard)


def require_field(data, key):
    value = data.get(key)
    if not value:
        sys.exit(f"Missing '{key}' in onboarding inputs.")
    return value


def require_env(name):
    value = os.environ.get(name)
    if not value:
        sys.exit(f"Set {name} before running (see REPRODUCE_IOS_APP_ATTEST_PROOF.md).")
    return value


def main():
    parser = argparse.ArgumentParser(
        description="Submit composed FEN onboarding with a real device App Attest assertion."
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("FEN_BASE_URL", "http://localhost:3000"),
        help="Backend base URL reachable from this Mac (default: http://localhost:3000). "
        "The Mac talks to the backend directly, so the Cloudflare tunnel is not needed here.",
    )
    parser.add_argument(
        "--inputs-file",
        help="Path to the onboarding-inputs JSON from the app. If omitted, reads stdin, then the clipboard.",
    )
    args = parser.parse_args()

    inputs = read_inputs(args)
    subject_id = require_field(inputs, "subject_id")
    device_ref = require_field(inputs, "device_ref")
    challenge_nonce = require_field(inputs, "challenge_nonce")
    observed_at = require_field(inputs, "observed_at")
    expires_at = require_field(inputs, "expires_at")
    team_id = require_field(inputs, "team_id")
    bundle_id = require_field(inputs, "bundle_id")
    environment = require_field(inputs, "environment")
    assertion = require_field(inputs, "assertion")

    oidc_token = require_env("IDENTITY_MODEL_KEYCLOAK_TOKEN")
    oidc_issuer = require_env("IDENTITY_MODEL_KEYCLOAK_ISSUER")
    oidc_client_id = require_env("IDENTITY_MODEL_KEYCLOAK_CLIENT_ID")
    liveness_assertion = os.environ.get(
        "IDENTITY_MODEL_LIVENESS_EXPECTED_ASSERTION", "valid-live-presence"
    )

    namespace = f"real-device-{uuid.uuid4().hex[:12]}"

    # 1. Live-presence callback -> liveness input for onboarding.
    callback_body = {
        "provider_name": "StaticLivePresenceProvider",
        "provider_event_id": f"liveness-callback-{namespace}",
        "provider_subject_ref": f"liveness-subject-{namespace}",
        "sdk_or_api_version": "real-device-static/1.0",
        "assertion": liveness_assertion,
        "challenge_nonce": challenge_nonce,
        "device_ref": device_ref,
        "observed_at": observed_at,
        "expires_at": expires_at,
        "result": "passed",
        "pad_result": "passed",
        "assurance_level": "high",
        "retention_policy_refs": ["live-presence-retention@v1"],
        "client_context": {"platform": "iphone", "request_id": f"callback-{namespace}"},
    }
    status, body = post_json(args.base_url, CALLBACK_PATH, callback_body)
    if status != 200 or body.get("status") != "verified":
        sys.exit(
            "Live-presence callback failed "
            f"(HTTP {status}):\n{json.dumps(body, indent=2)}"
        )
    liveness = body.get("liveness")
    if liveness is None:
        sys.exit(f"Callback response missing 'liveness':\n{json.dumps(body, indent=2)}")
    print("live-presence callback: verified")

    # 2. Composed onboarding with the REAL App Attest assertion envelope.
    onboarding_body = {
        "subject_id": subject_id,
        "observed_at": observed_at,
        "id_namespace": namespace,
        "expected_device_ref": device_ref,
        "oidc": {
            "access_token": oidc_token,
            "issuer": oidc_issuer,
            "client_id": oidc_client_id,
            "provider_name": "Keycloak",
        },
        "app_attest": {
            "assertion": assertion,
            "challenge_nonce": challenge_nonce,
            "team_id": team_id,
            "bundle_id": bundle_id,
            "environment": environment,
        },
        "liveness": liveness,
        "identity_proofing": {
            "provider_name": "Persona",
            "workflow_id": f"persona-workflow-{namespace}",
            "provider_event_id": f"persona-inquiry-{namespace}",
            "evidence_ref": f"identity-proofing-{namespace}",
            "evidence_types": ["government_id_document"],
            "verification_result": "passed",
            "assurance_level": "high",
            "asserted_attributes": [
                {"attribute": "legal_name", "value": "Real Device Proof", "confidence": "high"},
                {"attribute": "date_of_birth", "value": "1990-01-01", "confidence": "high"},
            ],
            "verified_at": observed_at,
            "audit_ref": f"persona-audit-{namespace}",
            "retention_policy_refs": ["identity-proof-retention@v1"],
        },
        "client_context": {
            "platform": "iphone",
            "request_id": f"onboarding-{namespace}",
            "app_version": "real-device-proof",
            "user_agent": "FenAppAttestProof/submit_onboarding.py",
        },
        "subject_kind": "human_person",
        "stable_profile": {"legal_name": "Real Device Proof", "date_of_birth": "1990-01-01"},
        "continuity_modality": "face",
    }
    status, body = post_json(args.base_url, ONBOARDING_PATH, onboarding_body)
    print(f"onboarding: HTTP {status}")
    print(json.dumps(body, indent=2))
    if status == 200 and body.get("status") == "accepted":
        summary = body.get("summary", {})
        print(
            "\nSUCCESS: "
            f"decision={summary.get('decision')} "
            f"assurance={summary.get('assurance_level')} "
            f"active_devices={summary.get('active_devices')} "
            f"facts={summary.get('committed_fact_count')}"
        )
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
