// Keys+Utils.swift
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

struct Keys {
    let privateKey: Data
    let publicKey: Data
    let jwk: JWK

    static let shared = Keys()
    
    private init() {
        self.privateKey = loadPEM(from: "guardian-test.private")
        self.publicKey = loadPEM(from: "guardian-test.public")
        self.jwk = loadJWK(from: "guardian-test.public")
    }
}

struct JWK: Codable {
    let keyType: String
    let algorithm: String
    let usage: String
    let modulus: String
    let exponent: String

    enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case algorithm = "alg"
        case usage = "use"
        case modulus = "n"
        case exponent = "e"
    }
}

private func loadPEM(from filename: String) -> Data {
    let bundle = Bundle(for: GuardianSpec.self)
    let path = bundle.path(forResource: filename, ofType: "pem")!
    let data = try! Data(contentsOf: URL(fileURLWithPath: path))
    let pemString = String(data: data, encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines)
    let parts = pemString.components(separatedBy: .newlines)
    let base64 = parts[1...parts.count-2].joined()
    let decoded = Data(base64Encoded: base64)!
    return decoded
}

private func loadJWK(from filename: String) -> JWK {
    let decoder = JSONDecoder()
    let bundle = Bundle(for: GuardianSpec.self)
    let path = bundle.path(forResource: filename, ofType: "json")!
    let data = try! Data(contentsOf: URL(fileURLWithPath: path))
    let jwk = try! decoder.decode(JWK.self, from: data)
    return jwk
}
