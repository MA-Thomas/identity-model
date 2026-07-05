import SwiftUI

struct ProofView: View {
    @StateObject private var model = ProofViewModel()

    var body: some View {
        NavigationStack {
            Form {
                Section("Backend") {
                    TextField("Base URL", text: $model.baseURLString)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    TextField("Subject ID", text: $model.subjectId)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button {
                        Task { await model.checkReady() }
                    } label: {
                        Label("Check Ready", systemImage: "bolt.horizontal")
                    }
                    .disabled(model.isBusy)
                }

                Section("Device") {
                    LabeledContent("Device Ref", value: model.deviceRef)
                    LabeledContent("Key ID", value: model.keyId ?? "none")
                    Button {
                        Task { await model.registerNewKey() }
                    } label: {
                        Label("Register New Key", systemImage: "key")
                    }
                    .disabled(model.isBusy)
                    Button(role: .destructive) {
                        model.resetLocalKey()
                    } label: {
                        Label("Clear Local Key", systemImage: "trash")
                    }
                    .disabled(model.isBusy)
                    Button(role: .destructive) {
                        model.rotateDeviceRef()
                    } label: {
                        Label("Rotate Device Ref", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(model.isBusy)
                }

                if let expectedApp = model.expectedApp {
                    Section("Expected App") {
                        LabeledContent("Team", value: expectedApp.teamId)
                        LabeledContent("Bundle", value: expectedApp.bundleId)
                        LabeledContent("App ID", value: expectedApp.appId ?? "pending")
                        LabeledContent("Environment", value: expectedApp.environment)
                    }
                }

                Section("Assertion") {
                    Button {
                        Task { await model.issueLivePresenceChallenge() }
                    } label: {
                        Label("Issue Live-Presence Challenge", systemImage: "person.crop.circle.badge.checkmark")
                    }
                    .disabled(model.isBusy || model.keyId == nil)

                    if let challenge = model.livePresenceChallenge {
                        LabeledContent("Challenge ID", value: challenge.challengeId)
                        LabeledContent("Expires", value: challenge.expiresAt)
                    }

                    Button {
                        Task { await model.generateAssertionEnvelope() }
                    } label: {
                        Label("Generate Assertion Envelope", systemImage: "checkmark.seal")
                    }
                    .disabled(model.isBusy || model.keyId == nil || model.livePresenceChallenge == nil)

                    Button {
                        model.copyAssertionEnvelope()
                    } label: {
                        Label("Copy Envelope", systemImage: "doc.on.doc")
                    }
                    .disabled(model.assertionEnvelope == nil)

                    Button {
                        model.copyOnboardingInputs()
                    } label: {
                        Label("Copy Onboarding Inputs", systemImage: "square.and.arrow.up.on.square")
                    }
                    .disabled(model.assertionEnvelope == nil)
                }

                if let envelope = model.assertionEnvelope {
                    Section("Envelope") {
                        Text(envelope)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                            .lineLimit(8)
                    }
                }

                Section("Log") {
                    if model.events.isEmpty {
                        Text("No events yet")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(Array(model.events.enumerated()), id: \.offset) { _, event in
                            Text(event)
                                .font(.footnote.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                }
            }
            .navigationTitle("FEN App Attest")
            .overlay {
                if model.isBusy {
                    ProgressView()
                        .padding()
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
                }
            }
        }
    }
}
