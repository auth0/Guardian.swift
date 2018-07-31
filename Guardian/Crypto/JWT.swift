// JWT.swift
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

struct JWT<S: Codable> {

    enum Algorithm: String, Codable {
        case rs256 = "RS256"

        func sign(value: Data, key: SecKey) throws -> Data {
            switch self {
            case .rs256:
                guard let sha256 = A0SHA(algorithm: "sha256"),
                    let rsa = A0RSA(key: key) else {
                    throw JWT.Error.cannotSign
                }
                let hash = sha256.hash(value)
                return rsa.sign(hash)
            }
        }

        func verify(signature: Data, with value: Data, using key: SecKey) throws -> Bool {
            switch self {
            case .rs256:
                guard let sha256 = A0SHA(algorithm: "sha256"),
                    let rsa = A0RSA(key: key) else {
                        throw JWT.Error.cannotVerify
                }
                let hash = sha256.hash(value)
                return rsa.verify(hash, signature: signature)
            }
        }
    }

    struct Header: Codable {
        let algorithm: Algorithm
        let type: String = "JWT"

        enum CodingKeys: String, CodingKey {
            case type = "typ"
            case algorithm = "alg"
        }
    }

    enum Error: String, Swift.Error {
        case invalid
        case badHeader
        case badClaims
        case badSignature
        case badSigningKey
        case badVerificationKey
        case cannotSign
        case cannotVerify
    }

    let header: Header
    let claimSet: S
    let signature: Data
    let parts: [String]

    init(claimSet: S, algorithm: JWT.Algorithm = .rs256, key: SecKey) throws {
        let header = Header(algorithm: algorithm)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let headerPart = try encoder.encode(header).base64URLEncodedString()
        let claimSetPart = try encoder.encode(claimSet).base64URLEncodedString()
        let signableParts = "\(headerPart).\(claimSetPart)"
        guard let value = signableParts.data(using: .utf8) else {
            throw JWT.Error.cannotSign
        }
        let signature = try algorithm.sign(value: value, key: key)
        let signaturePart = signature.base64URLEncodedString()
        self.header = header
        self.claimSet = claimSet
        self.signature = signature
        self.parts = [headerPart, claimSetPart, signaturePart]
    }

    init(string: String) throws {
        let parts = string.components(separatedBy: ".")
        guard parts.count == 3 else {
            throw JWT.Error.invalid
        }
        guard let headerData = Data(base64URLEncoded: parts[0]),
            let claimSetData = Data(base64URLEncoded: parts[1]),
            let signature = Data(base64URLEncoded: parts[2]) else {
                throw JWT.Error.invalid
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970

        self.header = try decoder.decode(Header.self, from: headerData)
        self.claimSet = try decoder.decode(S.self, from: claimSetData)
        self.signature = signature
        self.parts = parts
    }

    func verify(with key: SecKey) throws -> Bool {
        guard let data = "\(parts[0]).\(parts[1])".data(using: .utf8) else {
            throw JWT.Error.cannotVerify
        }
        return try self.header.algorithm.verify(signature: self.signature, with: data, using: key)
    }

    var string: String {
        return self.parts.joined(separator: ".")
    }
}

struct GuardianClaimSet: Codable, Equatable {
    let subject: String
    let issuer: String
    let audience: String
    let expireAt: Date
    let issuedAt: Date
    let method: String = "push"
    let status: Bool
    let reason: String?

    enum CodingKeys: String, CodingKey {
        case subject = "sub"
        case issuer = "iss"
        case audience = "aud"
        case expireAt = "exp"
        case issuedAt = "iat"

        case method = "auth0_guardian_method"
        case status = "auth0_guardian_accepted"
        case reason = "auth0_guardian_reason"
    }
}


