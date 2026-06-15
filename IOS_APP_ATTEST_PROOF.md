# iOS App Attest Proof Path

This is the smallest signed-iPhone path for exercising registered-key Apple App Attest assertions against the local FEN runtime.

The goal is not to make the iPhone app the identity model. The app produces Apple evidence. FEN verifies that evidence, stores the trusted App Attest public key registration, later verifies challenge-bound assertions from that registered key, and only then records normal FEN device-binding facts.

## Runtime Mode

Run the backend with `runtime-server` and opt into the Apple assertion verifier:

```sh
export IDENTITY_MODEL_APP_ATTEST_VERIFIER="apple_assertion"
export IDENTITY_MODEL_APP_ATTEST_TEAM_ID="TEAMID1234"
export IDENTITY_MODEL_APP_ATTEST_BUNDLE_ID="com.fen.identity"
export IDENTITY_MODEL_APP_ATTEST_ENVIRONMENT="development"
```

The signed app must use the same Apple team, bundle ID, and App Attest environment. A physical supported iPhone and a signed build with the App Attest entitlement are required. The phone also needs HTTPS access to the runtime, usually through a dev tunnel or a local TLS reverse proxy.

## Registration Flow

1. Ask FEN for an App Attest key-registration challenge:

```http
POST /mobile/app-attest/key-registration-challenge
Content-Type: application/json

{
  "client_context": {
    "platform": "iphone",
    "request_id": "registration-challenge-1"
  }
}
```

The response includes `challenge.challenge_nonce`, `issued_at`, `expires_at`, and the configured expected app identity.

2. In the signed iOS app, generate and attest a key:

```swift
import CryptoKit
import DeviceCheck

let service = DCAppAttestService.shared
guard service.isSupported else {
    throw ProofError.appAttestUnavailable
}

let keyId = try await service.generateKey()
let challengeHash = Data(SHA256.hash(data: Data(challengeNonce.utf8)))
let attestationObject = try await service.attestKey(keyId, clientDataHash: challengeHash)
```

3. Post the native attestation object to FEN:

```http
POST /mobile/app-attest/key-registration
Content-Type: application/json

{
  "key_id": "<DCAppAttest keyId>",
  "device_ref": "<stable proof-app install/device ref>",
  "challenge_nonce": "<challenge.challenge_nonce>",
  "attestation_object_hex": "<hex attestationObject>",
  "client_context": {
    "platform": "iphone",
    "request_id": "registration-1"
  }
}
```

FEN verifies the native App Attest attestation object, extracts and validates the public key, and records the key in PostgreSQL. Later assertions must use this registered `key_id`.

## Assertion Flow

1. Issue the normal live-presence challenge:

```http
POST /mobile/identity-onboarding/live-presence-challenge
```

Use the returned `challenge_nonce` as the App Attest assertion challenge.

2. In iOS, generate an assertion with the registered key:

```swift
let assertionHash = Data(SHA256.hash(data: Data(livePresenceChallengeNonce.utf8)))
let assertionObject = try await service.generateAssertion(keyId, clientDataHash: assertionHash)
```

3. Wrap the native assertion object for the existing onboarding contract:

```text
apple-app-attest-assertion-object-v1
|hex(utf8(keyId))
|hex(utf8(deviceRef))
|hex(assertionObject)
|hex(utf8(assertedAtUtc))
|hex(utf8(expiresAtUtc))
|high
```

Remove the line breaks when sending it as `app_attest.assertion` in `POST /mobile/identity-onboarding`. The same `livePresenceChallengeNonce` goes in `app_attest.challenge_nonce` and in the liveness callback/onboarding liveness input.

## Proof App Checklist

- signed iOS app, not simulator-only
- App Attest entitlement enabled for the bundle ID
- runtime reachable over HTTPS from the phone
- matching `TEAM_ID`, bundle ID, and development/production App Attest environment
- Keycloak login/token path available to the app
- key-registration challenge endpoint called before `attestKey`
- registration endpoint called before identity onboarding
- live-presence challenge nonce used for `generateAssertion`
- onboarding request sends the assertion-object envelope, not raw base64
