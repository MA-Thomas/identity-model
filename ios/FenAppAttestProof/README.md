# FEN App Attest Proof

This is a deliberately small signed-iPhone proof app for the backend contract in `IOS_APP_ATTEST_PROOF.md`.

The app does three things:

- registers a real App Attest key through `POST /mobile/app-attest/key-registration-challenge` and `POST /mobile/app-attest/key-registration`
- issues a live-presence challenge through `POST /mobile/identity-onboarding/live-presence-challenge`
- generates the registered-key assertion envelope expected by `POST /mobile/identity-onboarding`

## Xcode Setup

1. Open `FenAppAttestProof.xcodeproj`.
2. Select the `FenAppAttestProof` target.
3. Set the signing team to the same Apple team used by the backend `IDENTITY_MODEL_APP_ATTEST_TEAM_ID`.
4. Set the bundle identifier to the backend `IDENTITY_MODEL_APP_ATTEST_BUNDLE_ID`.
5. Keep `APP_ATTEST_ENVIRONMENT=development` for local/device proof builds unless the backend is configured for production.
6. Run on a physical iPhone. App Attest does not work as the real proof path on a simulator.

The entitlements file uses `$(APP_ATTEST_ENVIRONMENT)` for `com.apple.developer.devicecheck.appattest-environment`.

## Runtime Expectations

Run the backend with `runtime-server` and:

```sh
export IDENTITY_MODEL_APP_ATTEST_VERIFIER="apple_assertion"
export IDENTITY_MODEL_APP_ATTEST_TEAM_ID="YOURTEAMID"
export IDENTITY_MODEL_APP_ATTEST_BUNDLE_ID="com.example.your.bundle"
export IDENTITY_MODEL_APP_ATTEST_ENVIRONMENT="development"
```

The phone must reach the backend over HTTPS. A dev tunnel or local TLS reverse proxy is usually the easiest path.

## Proof Flow

1. Enter the backend base URL in the app.
2. Tap **Register New Key**.
3. Tap **Issue Live-Presence Challenge**.
4. Tap **Generate Assertion Envelope**.
5. Copy the assertion envelope into the composed onboarding request as `app_attest.assertion`.

The app stores the generated `device_ref` and accepted App Attest `keyId` in Keychain so a later assertion can use the same registered key.
