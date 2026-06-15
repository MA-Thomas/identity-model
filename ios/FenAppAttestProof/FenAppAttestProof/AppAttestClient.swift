import CryptoKit
import DeviceCheck
import Foundation

struct AppAttestClient {
    var isSupported: Bool {
        DCAppAttestService.shared.isSupported
    }

    func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            DCAppAttestService.shared.generateKey { keyId, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let keyId {
                    continuation.resume(returning: keyId)
                } else {
                    continuation.resume(throwing: AppAttestProofError.missingKeyId)
                }
            }
        }
    }

    func attestKey(_ keyId: String, challengeNonce: String) async throws -> Data {
        let challengeHash = Data(SHA256.hash(data: Data(challengeNonce.utf8)))
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            DCAppAttestService.shared.attestKey(keyId, clientDataHash: challengeHash) { attestationObject, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let attestationObject {
                    continuation.resume(returning: attestationObject)
                } else {
                    continuation.resume(throwing: AppAttestProofError.missingAttestationObject)
                }
            }
        }
    }

    func generateAssertion(keyId: String, challengeNonce: String) async throws -> Data {
        let challengeHash = Data(SHA256.hash(data: Data(challengeNonce.utf8)))
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: challengeHash) { assertionObject, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let assertionObject {
                    continuation.resume(returning: assertionObject)
                } else {
                    continuation.resume(throwing: AppAttestProofError.missingAssertionObject)
                }
            }
        }
    }
}

enum AppAttestProofError: LocalizedError {
    case appAttestUnavailable
    case invalidBackendURL
    case missingKeyId
    case missingAttestationObject
    case missingAssertionObject
    case missingExpectedApp
    case missingLivePresenceChallenge
    case missingAssertionEnvelope

    var errorDescription: String? {
        switch self {
        case .appAttestUnavailable:
            return "App Attest is not available on this device."
        case .invalidBackendURL:
            return "Enter a valid backend URL."
        case .missingKeyId:
            return "No App Attest key ID was returned."
        case .missingAttestationObject:
            return "No App Attest attestation object was returned."
        case .missingAssertionObject:
            return "No App Attest assertion object was returned."
        case .missingExpectedApp:
            return "Register a key first so the app can use the backend expected-app context."
        case .missingLivePresenceChallenge:
            return "Issue a live-presence challenge before generating an assertion."
        case .missingAssertionEnvelope:
            return "Generate an assertion envelope before copying it."
        }
    }
}
