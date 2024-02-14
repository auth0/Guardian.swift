// DataRSAPrivateKeyCreationSpec.swift
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

class DataRSAPrivateKeyCreationSpec: QuickSpec {
    override class func spec() {

        describe("new") {

            it("should return a key") {
                expect({ try DataRSAPrivateKey.new() }).toNot(raiseException())
            }

            it("should different keys") {
                let key1 = try! DataRSAPrivateKey.new()
                let key2 = try! DataRSAPrivateKey.new()
                expect(key1.secKey).toNot(equal(key2.secKey))
            }

            it("should allow sign") {
                let key = try! DataRSAPrivateKey.new()
                expect(SecKeyIsAlgorithmSupported(key.secKey, .sign, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256)).to(beTrue())
            }

            it("should have data") {
                let key = try! DataRSAPrivateKey.new()
                expect(key.data).toNot(beEmpty())
            }

            it("should have the right size") {
                let key = try! DataRSAPrivateKey.new()
                let attr = KeychainBot.shared.attributes(of: key.secKey)
                expect(attr[String(kSecAttrKeySizeInBits)] as? Int).to(equal(2048))
            }

            it("should have the right type") {
                let key = try! DataRSAPrivateKey.new()
                let attr = KeychainBot.shared.attributes(of: key.secKey)
                expect(attr[String(kSecAttrKeyType)] as? String).to(equal(String(kSecAttrKeyTypeRSA)))
            }
        }
    }
}
