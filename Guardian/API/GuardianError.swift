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
    public let code: String
    public let description: String
    public let info: [String: Any]
    public let cause: Swift.Error?

    init(code: Code, description: String? = nil, info: [String: Any] = [:], cause: Swift.Error? = nil) {
        self.code = code.rawValue
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
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let code = try container.decode(String.self, forKey: .code)
        let description = try container.decodeIfPresent(String.self, forKey: .description) ?? code
        let remainderContainer = try decoder.container(keyedBy: AdditionalDataCodingKeys.self)
        let info = remainderContainer.decodeUnknownKeyValues(exclude: CodingKeys.self)
        self.code = code
        self.description = description
        self.info = info
        self.cause = nil
    }

    enum CodingKeys: String, CodingKey {
        case code = "errorCode"
        case description = "description"
    }
}

private struct AdditionalDataCodingKeys: CodingKey {
    var stringValue: String
    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    var intValue: Int?
    init?(intValue: Int) {
        self.intValue = intValue
        self.stringValue = String(intValue)
    }
}

    extension KeyedDecodingContainer where Key == AdditionalDataCodingKeys {
        func decodeUnknownKeyValues<T: CodingKey>(exclude keyedBy: T.Type) -> [String: Any] {
            var data = [String: Any]()

            for key in allKeys {
                if keyedBy.init(stringValue: key.stringValue) == nil {
                    if let value = try? decode(String.self, forKey: key) {
                        data[key.stringValue] = value
                    } else if let value = try? decode(Bool.self, forKey: key) {
                        data[key.stringValue] = value
                    } else if let value = try? decode(Int.self, forKey: key) {
                        data[key.stringValue] = value
                    } else if let value = try? decode(Double.self, forKey: key) {
                        data[key.stringValue] = value
                    } else if let value = try? decode(Float.self, forKey: key) {
                        data[key.stringValue] = value
                    } else {
                        print("Key \(key.stringValue) type not supported")
                    }
                }
            }

            return data
        }
}
