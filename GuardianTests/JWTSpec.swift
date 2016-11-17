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

            let (publicKey, privateKey) = generateKeyPair(publicTag: UUID().uuidString,
                                                          privateTag: UUID().uuidString,
                                                          keyType: kSecAttrKeyTypeRSA,
                                                          keySize: RSAKeySize)!

            describe("encode with hardcoded key") {

                var jwt: String?

                beforeEach {
                    jwt = try? JWT.encode(claims: ["field": "value"], signingKey: ValidRSAPrivateKey.ref!)
                }

                it("should not return nil") {
                    expect(jwt).toNot(beNil())
                }

                it("should match hardcoded jwt") {
                    expect(jwt!).to(equal("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaWVsZCI6InZhbHVlIn0.D62W-L6QmF6cgNgHv5KcTVEGjupI-R7A3Fjv9667rh-gcVx7gni0thhkcyn-MypSSX-10mJI3EsBK3zhSkAmTAyQPKn1nIBPXKguJhpcp7eQnGLRuWzIYFgqSS-N6JQ5aZ5HVKLAxY0SwWagi46vDhykTQcvjhmFRgfxfoLR7WawXrYIFsyb0TZFmtaGUR7GlZ658ij5re8Lv-PC-wQQhDqMJKFrGtBuEOwqXdNXp05df4Cu--Yp0Q-FtXakYU-4TIeblNNOvq-gMgmRqwCC2oS0p7c6hIrqU2g43hbzqDqX4DH4LpfmmXmPHq4O3qjCFgaD88t4hwqF3B1FWJ3XBxiLwWO0Ah4ptRkwdBAEXN0uXN0sNGYwpbqQ8fWIJBIf4HS2XOuEch0K_w5vweiFdm6e3Rgiiel7oBqt7F_31VPttEN15IvW3UPyQUs2gwD2D1HghkVOq9icbFrOrUYnbpOQHTD_AYYiaBBNt7ht9UTeBvjcQmphmVy_pTjfgDzDPxH8A0YZlxr10UnmHoTWrEAUOfXgt_UN0NPuRF6wnDD__wyvF_SlWyW-Os6Mo7xUHZlstDe88UaUJGV1py5Qqj_E87VE2bHPIKXM6MfV9qgLG7QHFMp5_WPxE-979TBgrQ4LRFA24sYDErtz2JBuQmsjjzXG-uPK1-Q2N0Ad0dE"))
                }

                it("should verify successfuly with correct key") {
                    let claims = try? JWT.verify(string: jwt!, publicKey: ValidRSAPublicKey.ref!)
                    expect(claims).toNot(beNil())
                }

                it("should fail verify with incorrect key") {
                    let claims = try? JWT.verify(string: jwt!, publicKey: publicKey)
                    expect(claims).to(beNil())
                }
            }

            describe("encode with generated keys") {

                let jwt = try? JWT.encode(claims: ["string": "hello", "number": 7, "boolean": true],
                                          signingKey: privateKey)

                it("should not return nil") {
                    expect(jwt).toNot(beNil())
                }

                describe("should verify successfuly with correct key") {

                    let claims = try? JWT.verify(string: jwt!, publicKey: publicKey)

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
                    let claims = try? JWT.verify(string: jwt!, publicKey: ValidRSAPublicKey.ref!)
                    expect(claims).to(beNil())
                }
            }
        }
    }
}
