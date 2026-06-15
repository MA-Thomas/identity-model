import Foundation

struct ClientContext: Codable {
    var platform = "iphone"
    var requestId: String?
    var appVersion: String?
    var userAgent: String?
}

struct APIErrorBody: Codable, Equatable {
    var code: String
    var message: String
}

struct ExpectedApp: Codable, Equatable {
    var teamId: String
    var bundleId: String
    var appId: String?
    var environment: String
}

struct ExpectedAppInput: Codable, Equatable {
    var teamId: String
    var bundleId: String
    var environment: String
}

struct RegistrationChallengeRequest: Codable {
    var clientContext: ClientContext?
}

struct RegistrationChallengeResponse: Codable {
    var status: String
    var challenge: RegistrationChallenge?
    var requestId: String?
    var error: APIErrorBody?
}

struct RegistrationChallenge: Codable, Equatable {
    var challengeNonce: String
    var issuedAt: String
    var expiresAt: String
    var expectedApp: ExpectedApp
}

struct RegistrationRequest: Codable {
    var keyId: String
    var deviceRef: String
    var challengeNonce: String
    var attestationObjectHex: String
    var clientContext: ClientContext?
}

struct RegistrationResponse: Codable {
    var status: String
    var registration: RegistrationSummary?
    var requestId: String?
    var error: APIErrorBody?
}

struct RegistrationSummary: Codable, Equatable {
    var keyId: String
    var deviceRef: String
    var teamId: String
    var bundleId: String
    var appId: String
    var environment: String
    var registeredAt: String
    var attestationChallengeNonce: String
    var attestationFormat: String
}

struct LivePresenceChallengeRequest: Codable {
    var subjectId: String?
    var expectedDeviceRef: String?
    var expectedApp: ExpectedAppInput
    var clientContext: ClientContext?
}

struct LivePresenceChallengeResponse: Codable {
    var status: String
    var challenge: LivePresenceChallenge?
    var requestId: String?
    var error: APIErrorBody?
}

struct LivePresenceChallenge: Codable, Equatable {
    var challengeId: String
    var challengeNonce: String
    var intendedWorkflow: String
    var expectedSubjectId: String?
    var expectedDeviceRef: String?
    var expectedApp: ExpectedApp
    var issuedAt: String
    var expiresAt: String
    var retryPolicyRefs: [String]
    var manualReviewPolicyRefs: [String]
    var retentionPolicyRefs: [String]
    var providerHandoff: LivePresenceProviderHandoff
}

struct LivePresenceProviderHandoff: Codable, Equatable {
    var providerName: String
    var challengeNonce: String
    var handoffUri: String?
    var callbackPath: String
    var expiresAt: String
    var retentionPolicyRefs: [String]
}

struct EmptyResponse: Codable {}
