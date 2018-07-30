// LegacyGuardianError.swift
//
// Copyright (c) 2016 Auth0 (http://auth0.com)
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

private let internalErrorMessage = "a0.guardian.internal.unknown_error"
private let invalidPayloadMessage = "a0.guardian.internal.invalid_payload"
private let invalidEnrollmentUriMessage = "a0.guardian.internal.invalid_enrollment_uri"
private let invalidBase32SecretMessage = "a0.guardian.internal.invalid_base32_secret"
private let invalidJWKMessage = "a0.guardian.internal.invalid_jwk"
private let invalidOTPAlgorithmMessage = "a0.guardian.internal.invalid_otp_algorithm"
private let invalidNotificationActionIdentifierMessage = "a0.guardian.internal.invalid_notification_action_identifier"
private let invalidAsymmetricKeyMessage = "a0.guardian.internal.invalid.assymmetric.key"
private let notFoundPublicKeyMessage = "a0.guardian.internal.no.public.key"
private let failedCreationAsymmetricKeyMessage = "a0.guardian.internal.failed.creation.assymmetric.key"
private let failedStoreAsymmetricKeyMessage = "a0.guardian.internal.failed.store.assymmetric.key"
private let notFoundPrivateKeyMessage = "a0.guardian.internal.no.private.key"

/**
 An `Error` that encapsulates server and other possible internal errors
 */
public class LegacyGuardianError: Swift.Error, CustomStringConvertible {

    let info: [String: Any]?
    let statusCode: Int
    
    init(info: [String: Any], statusCode: Int) {
        self.info = info
        self.statusCode = statusCode
    }
    
    init(string: String, statusCode: Int = 0, cause: Swift.Error? = nil) {
        var info: [String: Any] = [
            "errorCode": string
        ]
        if let cause = cause {
            info["cause"] = cause
        }
        self.statusCode = statusCode
        self.info = info
    }

    /**
     The code of the error serves as an identifier for the cause of failure.

     You may want to take certain actions based on this value, like displaying
     different error messages to the user.
     */
    public var errorCode: String {
        guard let errorCode = self.info?["errorCode"] as? String else {
            return internalErrorMessage
        }
        return errorCode;
    }

    /**
     The representation to be used when converting an instance to a string, 
     conforming to the `CustomStringConvertible` protocol.
     */
    public var description: String {
        return "GuardianError(errorCode=\(errorCode), info=\(info ?? [:]))"
    }
}

internal extension LegacyGuardianError {
    static var internalError: LegacyGuardianError {
        return LegacyGuardianError(string: internalErrorMessage)
    }

    static var invalidBase32Secret: LegacyGuardianError {
        return LegacyGuardianError(string: invalidBase32SecretMessage)
    }

    static var invalidJWK: LegacyGuardianError {
        return LegacyGuardianError(string: invalidJWKMessage)
    }

    static var invalidOTPAlgorithm: LegacyGuardianError {
        return LegacyGuardianError(string: invalidOTPAlgorithmMessage)
    }

    static var invalidPayload: LegacyGuardianError {
        return LegacyGuardianError(string: invalidPayloadMessage)
    }

    static var invalidEnrollmentUri: LegacyGuardianError {
        return LegacyGuardianError(string: invalidEnrollmentUriMessage)
    }

    static var invalidNotificationActionIdentifier: LegacyGuardianError {
        return LegacyGuardianError(string: invalidNotificationActionIdentifierMessage)
    }

    static func invalidAsymmetricKey(cause: Swift.Error? = nil) -> LegacyGuardianError {
        return LegacyGuardianError(string: invalidAsymmetricKeyMessage, cause: cause)
    }

    static var notFoundPublicKey: LegacyGuardianError {
        return LegacyGuardianError(string: notFoundPublicKeyMessage)
    }

    static func notFoundPrivateKey(tag: String) -> LegacyGuardianError {
        return LegacyGuardianError(info: [
            "errorCode": notFoundPrivateKeyMessage,
            "tag": tag
            ], statusCode: 0)
    }

    static func failedCreationAsymmetricKey(cause: Swift.Error) -> LegacyGuardianError {
        return LegacyGuardianError(string: failedCreationAsymmetricKeyMessage, cause: cause)
    }

    static var failedStoreAsymmetricKey: LegacyGuardianError {
        return LegacyGuardianError(string: failedStoreAsymmetricKeyMessage)
    }
}
