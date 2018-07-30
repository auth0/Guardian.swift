// JWT.swift
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

struct JWT {

    static func encode(claims: [String: Any],
                       signingKey: SecKey) throws -> String {
        let header = [
            "alg": "RS256",
            "typ": "JWT"
        ]
        let jsonHeader = try JSONSerialization.data(withJSONObject: header, options: [])
        let jsonPayload = try JSONSerialization.data(withJSONObject: claims, options: [])
        let message = jsonHeader.base64URLEncodedString() + "." + jsonPayload.base64URLEncodedString()

        guard let data = message.data(using: .utf8) else {
            throw GuardianError(code: .cannotSignTransactionChallenge, description: "invalid jwt payload")
        }
        guard let sha256 = A0SHA(algorithm: "sha256"), let rsa = A0RSA(key: signingKey) else {
            throw GuardianError(code: .cannotSignTransactionChallenge, description: "invalid sign algorithm")
        }
        let hash = sha256.hash(data)
        let signature = rsa.sign(hash)
        return message + "." + signature.base64URLEncodedString()
    }

    static func verify(string: String,
                       publicKey: SecKey) throws -> [String: Any] {
        let components = string.components(separatedBy: ".")
        guard components.count == 3,
            let jsonHeader = Data(base64URLEncoded: components[0]),
            let header = (try? JSONSerialization.jsonObject(with: jsonHeader, options: [])) as? [String: Any],
            let alg = header["alg"] as? String, alg == "RS256",
            let typ = header["typ"] as? String, typ == "JWT",
            let jsonClaims = Data(base64URLEncoded: components[1]),
            let claims = (try? JSONSerialization.jsonObject(with: jsonClaims, options: [])) as? [String: Any],
            let signature = Data(base64URLEncoded: components[2])
            else {
                throw GuardianError(code: .cannotSignTransactionChallenge, description: "invalid jwt")
        }
        guard let sha256 = A0SHA(algorithm: "sha256"), let rsa = A0RSA(key: publicKey) else {
            throw GuardianError(code: .cannotSignTransactionChallenge, description: "invalid sign algorithm")
        }
        let message = components[0] + "." + components[1]
        guard let data = message.data(using: .utf8) else {
            throw GuardianError(code: .cannotSignTransactionChallenge, description: "invalid jwt payload")
        }
        let hash = sha256.hash(data)
        guard true == rsa.verify(hash, signature: signature) else {
            throw GuardianError(code: .cannotSignTransactionChallenge, description: "invalid jwt signature")
        }
        return claims
    }
}
