// JWTSpec.swift
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

import Quick
import Nimble

@testable import Guardian

class JWTSpec: QuickSpec {

    override func spec() {

        describe("JWT with RS256") {

            let signingKey = try! DataRSAPrivateKey(data: Keys.shared.privateKey)
            let verificationKey = try! AsymmetricPublicKey(privateKey: signingKey.secKey)
            let anotherVerificationKey = try! AsymmetricPublicKey(privateKey: DataRSAPrivateKey.new().secKey)

            describe("encode with hardcoded key") {

                var jwt: String?

                beforeEach {
                    jwt = try? JsonWebToken.encode(claims: ["field": "value"], signingKey: signingKey.secKey)
                }

                it("should not return nil") {
                    expect(jwt).toNot(beNil())
                }

                it("should match hardcoded jwt") {
                    expect(jwt!).to(equal("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaWVsZCI6InZhbHVlIn0.fxZ42chl-gGSNLT9LfJbnXsN7dliEGw-iA7CHzbmUsUb9-Ha0StKTXvh0iXJKQFxGMddGPFPOiN7FSTn3aVKYPNwrgIomsZXgYsw6gbs6yFD4aU7SSKYUAel0-rsr77lIcsALihZesuiEyerrZjypyOn-c2MJZE0ZIWaBaMXBQiGXm0MaUaeVkO4pFhO6pUTITIj5w0LkeK0SuzttgIGPbbmsQELMMocHEEqLNF0hMbSFjqjfXvWPUk8uH-uKawn1rhEK9Q6EdLO6bm8lm93WSpuiuR83zd7L88hZxHzbYnvBKQyzV4tKd4e1MvdAvuSEsdJnoTu933nR4SJzEYViA"))
                }

                it("should verify successfuly with correct key") {
                    let claims = try? JsonWebToken.verify(string: jwt!, publicKey: verificationKey.secKey)
                    expect(claims).toNot(beNil())
                }

                it("should fail verify with incorrect key") {
                    let claims = try? JsonWebToken.verify(string: jwt!, publicKey: anotherVerificationKey.secKey)
                    expect(claims).to(beNil())
                }
            }

            describe("encode with generated keys") {

                let jwt = try? JsonWebToken.encode(claims: ["string": "hello", "number": 7, "boolean": true],
                                          signingKey: signingKey.secKey)

                it("should not return nil") {
                    expect(jwt).toNot(beNil())
                }

                describe("should verify successfuly with correct key") {

                    let claims = try? JsonWebToken.verify(string: jwt!, publicKey: verificationKey.secKey)

                    it("should not be nil") {
                        expect(claims).toNot(beNil())
                    }

                    describe("should contain fields") {

                        it("with string") {
                            let value = claims?["string"] as? String
                            expect(value).toNot(beNil())
                            expect(value).to(equal("hello"))
                        }

                        it("with number") {
                            let value = claims?["number"] as? Double
                            expect(value).toNot(beNil())
                            expect(value).to(equal(7))
                        }

                        it("with boolean") {
                            let value = claims?["boolean"] as? Bool
                            expect(value).toNot(beNil())
                            expect(value).to(equal(true))
                        }
                    }
                }

                it("should fail verify with incorrect key") {
                    let claims = try? JsonWebToken.verify(string: jwt!, publicKey: anotherVerificationKey.secKey)
                    expect(claims).to(beNil())
                }
            }
        }
    }
}
