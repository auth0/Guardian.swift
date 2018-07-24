// DataRSAPublicKey.swift
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

/// Public key that is used to verify AuthN guardian responses
public struct AsymmetricPublicKey {
    public let secKey: SecKey

    /**
     Creates a new instance from a private key
     - parameter privateKey: `SecKey` of the private key from where to extract the public one
     - throws: `GuardianError` if the key cannot be exported
    */
    public init(privateKey: SecKey) throws {
        self.secKey = try publicKey(from: privateKey)
    }
}

extension AsymmetricPublicKey: VerificationKey, PublicKeyDataConvertible, ASNPublicKeyDecodable {
    public var data: Data? { return try? export(key: self.secKey) }
}

extension SigningKey {
    /**
     Utility method to obtain verification key from a signing key
     - returns: the verification key of the signing key
     - throws: `GuardianError` if the key cannot be obtained
    */
    public func verificationKey() throws -> VerificationKey {
        return try AsymmetricPublicKey(privateKey: self.secKey)
    }
}
