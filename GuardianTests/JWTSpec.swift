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

        var signingKey: SigningKey!
        var verificationKey: AsymmetricPublicKey!

        beforeEach {
            signingKey = try! DataRSAPrivateKey.new()
            verificationKey = try! AsymmetricPublicKey(privateKey: signingKey.secKey)
        }

        describe("signature") {

            var jwt: JWT<TestClaimSet>?

            describe("RS256") {

                describe("test keys") {
                    let aToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmaWVsZCI6InZhbHVlIn0.eBuXdca1vVkJKG8af4TAkokhFU_xnflc7Cx1FyIEQksS5sqsVxFTV_LTgytJCHJUlLCHzcUzTrNLJCNM8-yN0ft274fcuM3MsbQJIsPKyhoZKqu9TLRqeBJNm984shcGaXIb-Get7tsUU-riYf2V5kIHNj6q0Dn46VG8yzdWagCOOryU2kk5Ohdkytk-LHDSsrGWqRYv4eT6y_WGYuMK7NJISMMl9Q-pkwcFo3D3wa2QUMoVsKvlIe4GV9YTP5HHizSaQGENClpvvtoGpgCRE1j44a1hj6CN-p5ZnFxVf98o0ntiJcUo6DTKufb7JGzyFq0HyZoXiIKFMpRjw7Od0A"
                    let signingKey = try! DataRSAPrivateKey(data: Keys.shared.privateKey)
                    let verificationKey = try! AsymmetricPublicKey(privateKey: signingKey.secKey)
                    let anotherVerificationKey = try! AsymmetricPublicKey(privateKey: DataRSAPrivateKey.new().secKey)

                    beforeEach {
                        jwt = try? JWT(claimSet: TestClaimSet(field: "value"), key: signingKey.secKey)
                    }

                    it("should match hardcoded jwt") {
                        expect(jwt?.string).to(equal(aToken))
                    }

                    it("should match header part") {
                        expect(jwt?.parts[0]).to(equal("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"))
                    }

                    it("should match claims part") {
                        expect(jwt?.parts[1]).to(equal("eyJmaWVsZCI6InZhbHVlIn0"))
                    }

                    it("should match signature part") {
                        expect(jwt?.parts[2]).to(equal("eBuXdca1vVkJKG8af4TAkokhFU_xnflc7Cx1FyIEQksS5sqsVxFTV_LTgytJCHJUlLCHzcUzTrNLJCNM8-yN0ft274fcuM3MsbQJIsPKyhoZKqu9TLRqeBJNm984shcGaXIb-Get7tsUU-riYf2V5kIHNj6q0Dn46VG8yzdWagCOOryU2kk5Ohdkytk-LHDSsrGWqRYv4eT6y_WGYuMK7NJISMMl9Q-pkwcFo3D3wa2QUMoVsKvlIe4GV9YTP5HHizSaQGENClpvvtoGpgCRE1j44a1hj6CN-p5ZnFxVf98o0ntiJcUo6DTKufb7JGzyFq0HyZoXiIKFMpRjw7Od0A"))
                    }

                    it("should verify successfuly with correct key") {
                        expect {
                            let jwt: JWT<TestClaimSet>? = try? JWT(string: aToken)
                            return try jwt?.verify(with: verificationKey.secKey)
                        }.to(beTrue())
                    }

                    it("should fail verify with incorrect key") {
                        expect {
                            let jwt: JWT<TestClaimSet>? = try? JWT(string: aToken)
                            return try jwt?.verify(with: anotherVerificationKey.secKey)
                        }.to(beFalse())
                    }
                }

                describe("random keys") {

                    var token: String!

                    beforeEach {
                        let jwt: JWT<TestClaimSet> = try! JWT(claimSet: TestClaimSet(field: UUID().uuidString), key: signingKey.secKey)
                        token = jwt.string
                    }

                    it("should verify") {
                        let jwt: JWT<TestClaimSet>! = try? JWT(string: token)
                        expect(try? jwt.verify(with: verificationKey.secKey)).to(beTrue())
                    }

                    it("should fail verify with incorrect key") {
                        let jwt: JWT<TestClaimSet>! = try? JWT(string: token)
                        let anotherSigningKey = try! DataRSAPrivateKey.new()
                        let anotherVerificationKey = try! AsymmetricPublicKey(privateKey: anotherSigningKey.secKey)
                        expect(try? jwt.verify(with: anotherVerificationKey.secKey)).to(beFalse())
                    }
                }

            }
        }

        describe("guardian claims") {

            typealias GuardianJWT = JWT<GuardianClaimSet>

            var claims: GuardianClaimSet!

            beforeEach {
                claims = GuardianClaimSet(subject: UUID().uuidString, issuer: UUID().uuidString, audience: UUID().uuidString, expireAt: Date(), issuedAt: Date(), status: false, reason: UUID().uuidString)
            }

            it("should create instance") {
                expect(try? GuardianJWT(claimSet: claims, key: signingKey.secKey)).toNot(beNil())
            }

            it("should create jwt") {
                expect(try? GuardianJWT(claimSet: claims, key: signingKey.secKey).string).toNot(beEmpty())
            }

            it("should have correct alg") {
                expect(try? GuardianJWT(claimSet: claims, key: signingKey.secKey).header.algorithm).to(equal(.rs256))
            }

            it("should have correct type") {
                expect(try? GuardianJWT(claimSet: claims, key: signingKey.secKey).header.type).to(equal("JWT"))
            }

            it("should have signature") {
                expect(try? GuardianJWT(claimSet: claims, key: signingKey.secKey).signature).toNot(beEmpty())
            }

            describe("string token") {

                let aToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpYXQiOjE1MzI5OTAwNzQsImF1dGgwX2d1YXJkaWFuX3JlYXNvbiI6ImhhY2tlZCIsImF1dGgwX2d1YXJkaWFuX2FjY2VwdGVkIjpmYWxzZSwic3ViIjoiMzgxMzNGM0ItNTY2Mi00MzYxLUIyMTItQkRFQkJDODZDNUZGIiwiYXV0aDBfZ3VhcmRpYW5fbWV0aG9kIjoicHVzaCIsImV4cCI6MTUzMjk5MDE1MCwiYXVkIjoiOUU4QjNGNjYtOTAxRC00QjM2LUJGNkItMTFDRkNBRkMwMUExIiwiaXNzIjoiRUE3RThDMzAtREQ4Ny00M0IwLTg0MEEtMzc2MTUzMkU2ODkzIn0.g28ieoHqXkYlqZ8clIlIsPac04x9a8c0XEkFzvr17sOfnZUxnswUXm2J8Rf7syZ9zs_nW5WPS4o357FSAb1DA-CYQ_tzmFVE3rEqZ_KT0n2tnxMNw6G_fULIivdpan17gOb3jTjyDmfQBcodIhuOrglPDiA-AUNYEdqE8KYgNLBn0hRhfVw2L7PnQYSwdu-hAZgiIqqCSLQ5BdalyKk87LALoXpn5RH_CWbEjU6NSUb3h62gI7aIZpwqCww0ehp--IUBj-NBmFB4fFNOYOKC38RxV2bTIyK1QbwLmvv02Hj5WiVBt-KzZ8xAptmxWwsG7axYTYRYpFqbi6pkiWUzUw"

                it("should verify") {
                    let jwt = try! GuardianJWT(string: aToken)
                    let key = try! AsymmetricPublicKey(privateKey: DataRSAPrivateKey(data: Keys.shared.privateKey).secKey).secKey
                    expect(try? jwt.verify(with: key)).to(beTrue())
                }

                var jwt: GuardianJWT?

                beforeEach {
                    jwt = try? GuardianJWT(string: aToken)
                }

                it("should parse token") {
                    expect(jwt).toNot(beNil())
                }

                it("should have correct claims") {
                    let claims = GuardianClaimSet(subject: "38133F3B-5662-4361-B212-BDEBBC86C5FF", issuer: "EA7E8C30-DD87-43B0-840A-3761532E6893", audience: "9E8B3F66-901D-4B36-BF6B-11CFCAFC01A1", expireAt: Date(timeIntervalSince1970: 1532990150), issuedAt: Date(timeIntervalSince1970: 1532990074), status: false, reason: "hacked")
                    expect(jwt?.claimSet).to(equal(claims))
                }
            }
        }
    }
}

struct TestClaimSet: Codable {
    let field: String
}
