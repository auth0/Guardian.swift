// GuardianService.swift
//
// Copyright (c) 2026 Auth0 (http://auth0.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import Foundation
import UserNotifications
import Guardian

/// Every Guardian SDK call the sample makes, in one place. Each function matches
/// a section of the Guardian.swift README, so the two can be read side by side.
///
/// Completions are always called on the main queue, so callers can update UI
/// directly.
enum GuardianService {

    // MARK: - Tenant

    static let tenantDomainKey = "GuardianTenantDomain"
    static let defaultTenantDomain = "https://guardian-demo.us.auth0.com"

    /// The tenant the sample talks to. Resolved in order from the
    /// `-GuardianTenantDomain <url>` launch argument, the GUARDIAN_TENANT_DOMAIN
    /// build setting (written to Info.plist), then the Guardian demo tenant.
    static let tenantDomain: String = {
        if let domain = UserDefaults.standard.string(forKey: tenantDomainKey), !domain.isEmpty {
            return domain
        }
        if let domain = Bundle.main.object(forInfoDictionaryKey: tenantDomainKey) as? String, !domain.isEmpty {
            return domain
        }
        return defaultTenantDomain
    }()

    // MARK: - Enroll (README: "Enroll", "Signing & Verification Keys")

    /// Enrolls this device with the link encoded in an enrollment QR code.
    ///
    /// Each enrollment gets its own signing key. `KeychainRSAPrivateKey.new(with:)`
    /// returns the key already stored under a tag, so a fixed tag would share one
    /// key across enrollments. The key is deleted again if enrollment fails.
    static func enroll(usingUri uri: String,
                       notificationToken: String,
                       completion: @escaping (Swift.Result<GuardianState, Swift.Error>) -> Void) {
        let keyTag = "com.auth0.guardian.sample.signing-key.\(UUID().uuidString)"
        let signingKey: KeychainRSAPrivateKey
        let verificationKey: VerificationKey
        do {
            signingKey = try KeychainRSAPrivateKey.new(with: keyTag)
            verificationKey = try signingKey.verificationKey()
        } catch {
            GuardianState.deleteSigningKey(withTag: keyTag)
            return onMain(completion, .failure(error))
        }

        Guardian
            .enroll(forDomain: tenantDomain,
                    usingUri: uri,
                    notificationToken: notificationToken,
                    signingKey: signingKey,
                    verificationKey: verificationKey)
            .on(response: { event in
                // Log the status only: the response body carries the TOTP secret.
                #if DEBUG
                print("Enroll response: HTTP \(event.response.statusCode)")
                #endif
            })
            .start { result in
                switch result {
                case .success(let enrollment):
                    let state = GuardianState(identifier: enrollment.id,
                                              localIdentifier: enrollment.localIdentifier,
                                              signingKey: signingKey,
                                              otp: enrollment.totp,
                                              userId: enrollment.userId)
                    onMain(completion, .success(state))
                case .failure(let cause):
                    GuardianState.deleteSigningKey(withTag: keyTag)
                    onMain(completion, .failure(cause))
                }
            }
    }

    // MARK: - One-time codes (the SDK's totp(parameters:) generator)

    /// The current TOTP code for an enrollment that has TOTP, or nil.
    static func currentCode(for device: GuardianState) -> String? {
        guard let parameters = device.otp, let generator = try? Guardian.totp(parameters: parameters) else {
            return nil
        }
        return generator.stringCode()
    }

    // MARK: - Push notifications (README: "Allow a login request")

    /// The notification category that adds Allow and Deny actions to Guardian
    /// login requests. Register it with `UNUserNotificationCenter`.
    static func notificationCategory() -> UNNotificationCategory {
        let guardianCategory = Guardian.AuthenticationCategory.default
        let allowAction = UNNotificationAction(
            identifier: guardianCategory.allow.identifier,
            title: NSLocalizedString("Allow", comment: "Accept Guardian authentication request"),
            options: [.authenticationRequired] // Always request local AuthN
        )
        let denyAction = UNNotificationAction(
            identifier: guardianCategory.reject.identifier,
            title: NSLocalizedString("Deny", comment: "Reject Guardian authentication request"),
            options: [.destructive, .authenticationRequired] // Always request local AuthN
        )
        return UNNotificationCategory(
            identifier: guardianCategory.identifier,
            actions: [allowAction, denyAction],
            intentIdentifiers: [],
            options: [])
    }

    /// Parses a push payload into a Guardian login request, or nil if the push
    /// is not from Guardian.
    static func notification(from userInfo: [AnyHashable: Any]) -> Guardian.Notification? {
        return Guardian.notification(from: userInfo)
    }

    // MARK: - Allow and reject (README: "Allow a login request", "Reject a login request")

    static func allow(_ notification: Guardian.Notification,
                      device: GuardianState,
                      completion: @escaping (Swift.Result<Void, Swift.Error>) -> Void) {
        Guardian
            .authentication(forDomain: tenantDomain, device: device)
            .allow(notification: notification)
            .start { result in onMain(completion, voidResult(result)) }
    }

    static func reject(_ notification: Guardian.Notification,
                       device: GuardianState,
                       completion: @escaping (Swift.Result<Void, Swift.Error>) -> Void) {
        Guardian
            .authentication(forDomain: tenantDomain, device: device)
            .reject(notification: notification)
            .start { result in onMain(completion, voidResult(result)) }
    }

    /// Allows or rejects a login request from the Allow/Deny action the user
    /// picked on the notification itself.
    static func handleAction(withIdentifier identifier: String,
                             notification: Guardian.Notification,
                             device: GuardianState,
                             completion: @escaping (Swift.Result<Void, Swift.Error>) -> Void) {
        Guardian
            .authentication(forDomain: tenantDomain, device: device)
            .handleAction(withIdentifier: identifier, notification: notification)
            .start { result in onMain(completion, voidResult(result)) }
    }

    // MARK: - Rich consent (README: "Fetch rich consent details")

    /// Fetches what the user is asked to approve, for a login request that has
    /// a `transactionLinkingId`.
    static func fetchConsentDetails(consentId: String,
                                    notification: Guardian.Notification,
                                    device: GuardianState,
                                    completion: @escaping (Swift.Result<ConsentRequestedDetails, Swift.Error>) -> Void) {
        Guardian
            .consent(forDomain: tenantDomain)
            .fetch(consentId: consentId, transactionToken: notification.transactionToken, signingKey: device.signingKey)
            .start { result in
                switch result {
                case .success(let consent):
                    onMain(completion, .success(consent.requestedDetails))
                case .failure(let cause):
                    onMain(completion, .failure(cause))
                }
            }
    }

    // MARK: - Unenroll (README: "Unenroll")

    /// Deletes the enrollment on the tenant. The caller removes the local state
    /// and signing key once this succeeds.
    static func unenroll(_ device: GuardianState,
                         completion: @escaping (Swift.Result<Void, Swift.Error>) -> Void) {
        Guardian
            .api(forDomain: tenantDomain)
            .device(forEnrollmentId: device.identifier, userId: device.userId, signingKey: device.signingKey)
            .delete()
            .start { result in onMain(completion, voidResult(result)) }
    }

    // MARK: - Helpers

    private static func voidResult<T>(_ result: Guardian.Result<T>) -> Swift.Result<Void, Swift.Error> {
        switch result {
        case .success:
            return .success(())
        case .failure(let cause):
            return .failure(cause)
        }
    }

    private static func onMain<T>(_ completion: @escaping (Swift.Result<T, Swift.Error>) -> Void,
                                  _ result: Swift.Result<T, Swift.Error>) {
        DispatchQueue.main.async { completion(result) }
    }
}
