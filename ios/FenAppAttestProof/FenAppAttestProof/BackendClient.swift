import Foundation

struct BackendClient {
    var baseURL: URL

    func checkReady() async throws -> String {
        let url = try endpoint("/ready")
        let (data, response) = try await URLSession.shared.data(from: url)
        try validate(response: response, data: data)
        return String(data: data, encoding: .utf8) ?? "ready"
    }

    func issueRegistrationChallenge(requestId: String) async throws -> RegistrationChallenge {
        let response: RegistrationChallengeResponse = try await post(
            "/mobile/app-attest/key-registration-challenge",
            body: RegistrationChallengeRequest(
                clientContext: ClientContext(
                    requestId: requestId,
                    appVersion: appVersion,
                    userAgent: userAgent
                )
            )
        )
        try throwIfServerError(response.error)
        guard response.status == "issued", let challenge = response.challenge else {
            throw BackendError.unexpectedResponse("missing key-registration challenge")
        }
        return challenge
    }

    func registerKey(
        keyId: String,
        deviceRef: String,
        challengeNonce: String,
        attestationObject: Data,
        requestId: String
    ) async throws -> RegistrationSummary {
        let response: RegistrationResponse = try await post(
            "/mobile/app-attest/key-registration",
            body: RegistrationRequest(
                keyId: keyId,
                deviceRef: deviceRef,
                challengeNonce: challengeNonce,
                attestationObjectHex: attestationObject.fenHexString,
                clientContext: ClientContext(
                    requestId: requestId,
                    appVersion: appVersion,
                    userAgent: userAgent
                )
            )
        )
        try throwIfServerError(response.error)
        guard response.status == "registered", let registration = response.registration else {
            throw BackendError.unexpectedResponse("missing App Attest registration")
        }
        return registration
    }

    func issueLivePresenceChallenge(
        subjectId: String?,
        deviceRef: String,
        expectedApp: ExpectedApp,
        requestId: String
    ) async throws -> LivePresenceChallenge {
        let response: LivePresenceChallengeResponse = try await post(
            "/mobile/identity-onboarding/live-presence-challenge",
            body: LivePresenceChallengeRequest(
                subjectId: subjectId?.isEmpty == true ? nil : subjectId,
                expectedDeviceRef: deviceRef,
                expectedApp: ExpectedAppInput(
                    teamId: expectedApp.teamId,
                    bundleId: expectedApp.bundleId,
                    environment: expectedApp.environment
                ),
                clientContext: ClientContext(
                    requestId: requestId,
                    appVersion: appVersion,
                    userAgent: userAgent
                )
            )
        )
        try throwIfServerError(response.error)
        guard response.status == "issued", let challenge = response.challenge else {
            throw BackendError.unexpectedResponse("missing live-presence challenge")
        }
        return challenge
    }

    private func post<Response: Decodable, Body: Encodable>(
        _ path: String,
        body: Body
    ) async throws -> Response {
        let url = try endpoint(path)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try encoder.encode(body)

        let (data, response) = try await URLSession.shared.data(for: request)
        try validate(response: response, data: data)
        return try decoder.decode(Response.self, from: data)
    }

    private func endpoint(_ path: String) throws -> URL {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            throw BackendError.invalidBaseURL
        }
        let trimmedBasePath = components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let trimmedPath = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        components.path = [trimmedBasePath, trimmedPath]
            .filter { !$0.isEmpty }
            .joined(separator: "/")
        components.path = "/" + components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = components.url else {
            throw BackendError.invalidBaseURL
        }
        return url
    }

    private func validate(response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else {
            throw BackendError.unexpectedResponse("missing HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw BackendError.httpStatus(http.statusCode, body)
        }
    }

    private func throwIfServerError(_ error: APIErrorBody?) throws {
        if let error {
            throw BackendError.serverError(error.code, error.message)
        }
    }

    private var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        return encoder
    }

    private var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1"
    }

    private var userAgent: String {
        "FenAppAttestProof/\(appVersion)"
    }
}

enum BackendError: LocalizedError {
    case invalidBaseURL
    case httpStatus(Int, String)
    case serverError(String, String)
    case unexpectedResponse(String)

    var errorDescription: String? {
        switch self {
        case .invalidBaseURL:
            return "Backend URL is not valid."
        case let .httpStatus(status, body):
            return "Backend returned HTTP \(status): \(body)"
        case let .serverError(code, message):
            return "\(code): \(message)"
        case let .unexpectedResponse(message):
            return "Unexpected backend response: \(message)"
        }
    }
}
