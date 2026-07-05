import Combine
import Foundation
import UIKit

@MainActor
final class ProofViewModel: ObservableObject {
    @Published var baseURLString: String {
        didSet {
            UserDefaults.standard.set(baseURLString, forKey: Self.baseURLKey)
        }
    }
    @Published var subjectId: String
    @Published private(set) var deviceRef: String
    @Published private(set) var keyId: String?
    @Published private(set) var expectedApp: ExpectedApp?
    @Published private(set) var registration: RegistrationSummary?
    @Published private(set) var registrationChallenge: RegistrationChallenge?
    @Published private(set) var livePresenceChallenge: LivePresenceChallenge?
    @Published private(set) var assertionEnvelope: String?
    @Published private(set) var assertionAssertedAt: String?
    @Published private(set) var isBusy = false
    @Published private(set) var events: [String] = []

    private static let baseURLKey = "fen.proof.baseURL"
    private static let subjectIdKey = "fen.proof.subjectId"
    private static let deviceRefKey = "fen.proof.deviceRef"
    private static let keyIdKey = "fen.proof.keyId"

    private let keychain = KeychainStore()
    private let appAttest = AppAttestClient()

    init() {
        baseURLString = UserDefaults.standard.string(forKey: Self.baseURLKey) ?? "https://127.0.0.1:8443"
        subjectId = UserDefaults.standard.string(forKey: Self.subjectIdKey) ?? "subject-ios-proof"

        let loadedDeviceRef = try? keychain.load(Self.deviceRefKey)
        if let loadedDeviceRef, !loadedDeviceRef.isEmpty {
            deviceRef = loadedDeviceRef
        } else {
            let generated = "iphone-proof-\(UUID().uuidString.lowercased())"
            deviceRef = generated
            try? keychain.save(generated, for: Self.deviceRefKey)
        }

        keyId = try? keychain.load(Self.keyIdKey)
        appendEvent("Ready. App Attest supported: \(appAttest.isSupported ? "yes" : "no")")
    }

    func checkReady() async {
        await run("Checking backend readiness") { [self] in
            let text = try await backend().checkReady()
            appendEvent("Backend ready: \(text.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }

    func registerNewKey() async {
        await run("Registering App Attest key") { [self] in
            guard appAttest.isSupported else {
                throw AppAttestProofError.appAttestUnavailable
            }

            let requestId = "ios-registration-\(UUID().uuidString)"
            let challenge = try await backend().issueRegistrationChallenge(requestId: requestId)
            registrationChallenge = challenge
            expectedApp = challenge.expectedApp
            appendEvent("Registration challenge issued for \(challenge.expectedApp.appId ?? challenge.expectedApp.bundleId)")

            let newKeyId = try await appAttest.generateKey()
            let attestationObject = try await appAttest.attestKey(
                newKeyId,
                challengeNonce: challenge.challengeNonce
            )
            appendEvent("Generated attestation object: \(attestationObject.count) bytes")

            let accepted = try await backend().registerKey(
                keyId: newKeyId,
                deviceRef: deviceRef,
                challengeNonce: challenge.challengeNonce,
                attestationObject: attestationObject,
                requestId: "ios-registration-post-\(UUID().uuidString)"
            )
            keyId = accepted.keyId
            registration = accepted
            try keychain.save(accepted.keyId, for: Self.keyIdKey)
            appendEvent("Registered key \(accepted.keyId.prefix(12))... for \(accepted.deviceRef)")
        }
    }

    func issueLivePresenceChallenge() async {
        await run("Issuing live-presence challenge") { [self] in
            guard let expectedApp else {
                throw AppAttestProofError.missingExpectedApp
            }
            UserDefaults.standard.set(subjectId, forKey: Self.subjectIdKey)
            let challenge = try await backend().issueLivePresenceChallenge(
                subjectId: subjectId,
                deviceRef: deviceRef,
                expectedApp: expectedApp,
                requestId: "ios-live-presence-\(UUID().uuidString)"
            )
            livePresenceChallenge = challenge
            appendEvent("Live-presence challenge issued: \(challenge.challengeId)")
        }
    }

    func generateAssertionEnvelope() async {
        await run("Generating registered-key assertion") { [self] in
            guard let keyId, !keyId.isEmpty else {
                throw AppAttestProofError.missingKeyId
            }
            guard let challenge = livePresenceChallenge else {
                throw AppAttestProofError.missingLivePresenceChallenge
            }

            let assertionObject = try await appAttest.generateAssertion(
                keyId: keyId,
                challengeNonce: challenge.challengeNonce
            )
            let assertedAt = Self.iso8601Now()
            let envelope = [
                "apple-app-attest-assertion-object-v1",
                keyId.fenUTF8HexString,
                deviceRef.fenUTF8HexString,
                assertionObject.fenHexString,
                assertedAt.fenUTF8HexString,
                challenge.expiresAt.fenUTF8HexString,
                "high"
            ].joined(separator: "|")
            assertionEnvelope = envelope
            assertionAssertedAt = assertedAt
            appendEvent("Generated assertion envelope: \(assertionObject.count) assertion bytes")
        }
    }

    func copyAssertionEnvelope() {
        guard let assertionEnvelope else {
            appendEvent(AppAttestProofError.missingAssertionEnvelope.localizedDescription)
            return
        }
        UIPasteboard.general.string = assertionEnvelope
        appendEvent("Copied assertion envelope")
    }

    // Exports everything the Mac-side submit_onboarding.py script needs to submit
    // a composed identity-onboarding request bound to this live assertion. The
    // challenge nonce is single-use and expires, so submit promptly after copying.
    func copyOnboardingInputs() {
        guard let assertionEnvelope,
              let challenge = livePresenceChallenge,
              let assertedAt = assertionAssertedAt else {
            appendEvent("Generate an assertion envelope before copying onboarding inputs.")
            return
        }
        let inputs: [String: String] = [
            "base_url": baseURLString,
            "subject_id": subjectId,
            "device_ref": deviceRef,
            "challenge_nonce": challenge.challengeNonce,
            "observed_at": assertedAt,
            "expires_at": challenge.expiresAt,
            "team_id": challenge.expectedApp.teamId,
            "bundle_id": challenge.expectedApp.bundleId,
            "environment": challenge.expectedApp.environment,
            "assertion": assertionEnvelope,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: inputs, options: [.prettyPrinted, .sortedKeys]),
              let json = String(data: data, encoding: .utf8) else {
            appendEvent("Could not encode onboarding inputs.")
            return
        }
        UIPasteboard.general.string = json
        appendEvent("Copied onboarding inputs (submit promptly; challenge nonce expires \(challenge.expiresAt))")
    }

    func resetLocalKey() {
        try? keychain.delete(Self.keyIdKey)
        keyId = nil
        registration = nil
        registrationChallenge = nil
        livePresenceChallenge = nil
        assertionEnvelope = nil
        assertionAssertedAt = nil
        appendEvent("Cleared local App Attest key ID")
    }

    func rotateDeviceRef() {
        let generated = "iphone-proof-\(UUID().uuidString.lowercased())"
        try? keychain.save(generated, for: Self.deviceRefKey)
        deviceRef = generated
        resetLocalKey()
        appendEvent("Created new device ref")
    }

    private func backend() throws -> BackendClient {
        guard let url = URL(string: baseURLString), url.scheme != nil, url.host != nil else {
            throw AppAttestProofError.invalidBackendURL
        }
        return BackendClient(baseURL: url)
    }

    private func run(_ label: String, operation: @escaping () async throws -> Void) async {
        guard !isBusy else {
            return
        }
        isBusy = true
        appendEvent(label)
        do {
            try await operation()
        } catch {
            appendEvent("Error: \(error.localizedDescription)")
        }
        isBusy = false
    }

    private func appendEvent(_ message: String) {
        events.insert("[\(Self.iso8601Now())] \(message)", at: 0)
        if events.count > 40 {
            events.removeLast(events.count - 40)
        }
    }

    private static func iso8601Now() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date())
    }
}
