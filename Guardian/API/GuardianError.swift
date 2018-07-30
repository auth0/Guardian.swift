// Error.swift
//
// Copyright (c) 2018 Auth0 (http://auth0.com)
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

public struct GuardianError: Swift.Error {
    let code: Code
    let description: String
    let info: [String: Any]
    let cause: Swift.Error?

    init(code: Code, description: String? = nil, info: [String: Any] = [:], cause: Swift.Error? = nil) {
        self.code = code
        self.description = description ?? code.rawValue
        self.info = info
        self.cause = cause
    }

    enum Code: String {
        case invalidErollmentUri = "a0.guardian.internal.invalid.enrollment_uri"
        case invalidOTPSecret = "a0.guardian.internal.invalid.base32_secret"
        case invalidJWK = "a0.guardian.internal.invalid_jwk"
        case invalidOTPAlgorithm = "a0.guardian.internal.invalid.otp_algorithm"
        case invalidNotificationActionIdentifier = "a0.guardian.internal.invalid.notification_action_identifier"
        case invalidAsymmetricKey = "a0.guardian.internal.invalid.assymmetric_key"
        case notFoundPublicKey = "a0.guardian.internal.no.public_key"
        case failedCreationAsymmetricKey = "a0.guardian.internal.failed.creation_assymmetric_key"
        case failedStoreAsymmetricKey = "a0.guardian.internal.failed.store_assymmetric_key"
        case notFoundPrivateKey = "a0.guardian.internal.no.private_key"
        case cannotSignTransactionChallenge = "a0.guardian.internal.cannot.sign_challenge"
    }
}

extension GuardianError: Decodable {
    public init(from decoder: Decoder) throws {
        throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: [], debugDescription: "NOT IMPLEMENTED"))
    }
}
