// Models.swift
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

struct PushCredentials: Codable {
    private(set) var service = "APNS"
    let token: String
}

public struct RSAPublicJWK: Codable, Equatable {
    let keyType = "RSA"
    let usage = "sig"
    let algorithm = "RS256"
    let modulus: String
    let exponent: String

    enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case usage = "use"
        case algorithm = "alg"
        case modulus = "n"
        case exponent = "e"
    }
}

public struct Device: Encodable {
    let identifier: String
    let name: String
    let pushCredentials: PushCredentials
    let publicKey: RSAPublicJWK

    enum CodingKeys: String, CodingKey {
        case identifier
        case name
        case pushCredentials = "push_credentials"
        case publicKey = "public_key"
    }
}

public struct Enrollment: Decodable{
    let identifier: String
    let token: String
    let userId: String
    let issuer: String
    let totp: OTPParameters?

    enum CodingKeys: String, CodingKey {
        case identifier = "id"
        case token
        case userId = "user_id"
        case issuer
        case totp
    }
}

public struct Transaction: Codable {
    let challengeResponse: String

    enum CodingKeys: String, CodingKey {
        case challengeResponse = "challenge_response"
    }
}

public struct UpdatedDevice: Codable {

    let identifier: String?
    let name: String?
    let pushCredentials: PushCredentials?

    enum CodingKeys: String, CodingKey {
        case identifier
        case name
        case pushCredentials = "push_credentials"
    }
}

public struct ConsentRequestedDetails: Decodable {
    public let audience: String
    public let scope: [String]
    public let bindingMessage: String?
    public let authorizationDetails: [Json]
    
    enum CodingKeys: String, CodingKey {
        case audience
        case scope
        case bindingMessage = "binding_message"
        case authorizationDetails = "authorization_details"
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.audience = try container.decode(String.self, forKey: .audience)
        self.scope = try container.decodeIfPresent([String].self, forKey: .scope) ?? []
        self.bindingMessage = try? container.decode(String.self, forKey: .bindingMessage)
        self.authorizationDetails = try container.decodeIfPresent([Json].self, forKey: .authorizationDetails) ?? []
    }
    
    public func filterAuthorizationDetailsByType<T: AuthorizationDetailsType>(_ type: T.Type) -> [T] {
        return authorizationDetails
            .filter({$0["type"]?.stringValue == type.type})
            .compactMap({try? decode(T.self, from:encode(body:$0))});
    }
}

public protocol AuthorizationDetailsType: Codable {
    static var type: String { get }
}

public struct Consent: Decodable {
    
    public let consentId: String
    
    public let requestedDetails: ConsentRequestedDetails
    
    public let createdAt: String
    
    public let expiresAt: String
    
    enum CodingKeys: String, CodingKey {
        case consentId = "id"
        case requestedDetails = "requested_details"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
    }
}

public struct Auth0TelemetryInfo: Codable, Equatable {
    let appName: String
    let appVersion: String
    
    public init(name: String, version: String) {
        self.appName = name
        self.appVersion = version
    }
}
