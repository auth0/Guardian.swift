// ASNPublicKeyDecodableSpec.swift
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

import Quick
import Nimble
import Guardian

class ASNPublicKeyDecodableSpec: QuickSpec {

    override func spec() {

        let keys = Keys.shared
        let privateKey = try! DataRSAPrivateKey(data: keys.privateKey)
        let publicKey = try! AsymmetricPublicKey(privateKey: privateKey.secKey)

        describe("ASN parsing") {

            it("should return modulus") {
                let n = publicKey.attributes?.modulus
                    .base64EncodedString()
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "=", with: "")

                expect(n).to(equal(keys.jwk.modulus))
            }

            it("should return exponent") {
                let e = publicKey.attributes?.exponent
                    .base64EncodedString()
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "=", with: "")

                expect(e).to(equal(keys.jwk.exponent))
            }

        }

        describe("jwk") {

            it("should return a jwk") {
                let publicKey = try! DataRSAPrivateKey.new().verificationKey()
                expect(publicKey.jwk).toNot(beNil())
            }

            it("should have kty") {
                expect(publicKey.jwk?.keyType).to(equal(keys.jwk.keyType))
            }

            it("should have use") {
                expect(publicKey.jwk?.usage).to(equal(keys.jwk.usage))
            }

            it("should have alg") {
                expect(publicKey.jwk?.algorithm).to(equal(keys.jwk.algorithm))
            }

            it("should have n") {
                expect(publicKey.jwk?.modulus).to(equal(keys.jwk.modulus))
            }

            it("should have e") {
                expect(publicKey.jwk?.exponent).to(equal(keys.jwk.exponent))
            }


        }
    }
}
