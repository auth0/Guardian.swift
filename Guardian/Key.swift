// Key.swift
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

public protocol SigningKey {
    /**
     Returns the `SecKey` instance

     - important: This method might return nil if a key with this tag is not
     present in the keychain or if the type of the key is not
     appropriate.
     */
    var secKey: SecKey? { get }
}

public protocol VerificationKey {
    var jwk: [String: Any]? { get }
}

public protocol PublicKeyDataConvertible {
    var data: Data? { get }
}

extension VerificationKey where Self: ASNPublicKeyDecodable {

    public var jwk: [String : Any]? {
        guard let exponent = exponent, let modulus = modulus else { return nil }
        return [
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "e": exponent.base64URLEncodedString(),
            "n": modulus.base64URLEncodedString(),
        ]
    }
}
