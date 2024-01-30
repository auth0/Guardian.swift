// GuardianSpec.swift
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

class GuardianSpec: QuickSpec {
    
    override func spec() {

        beforeEach {
            stub(condition: { _ in return true }) { _ in
                return OHHTTPStubsResponse.init(error: NSError(domain: "com.auth0", code: -99999, userInfo: nil))
                }.name = "YOU SHALL NOT PASS!"
        }
        
        afterEach {
            OHHTTPStubs.removeAllStubs()
        }

        describe("api(forDomain:)") {

            it("should return api with domain only") {
                expect(Guardian.api(forDomain: "samples.guardian.auth0.com")).toNot(beNil())
            }

            it("should return api with http url") {
                expect(Guardian.api(forDomain: "https://samples.guardian.auth0.com")).toNot(beNil())
            }
        }

        describe("api(url:)") {

            it("should return api with url only") {
                expect(Guardian.api(url: URL(string: "https://samples.guardian.auth0.com")!)).toNot(beNil())
            }
        }

        describe("authentication(forDomain:, session:)") {

            let enrollment = EnrolledDevice(id: "ID", userId: "USER_ID", deviceToken: "TOKEN", notificationToken: "TOKEN", signingKey: try! DataRSAPrivateKey.new())

            it("should return authentication with domain only") {
                expect(Guardian.authentication(forDomain: "samples.guardian.auth0.com", device: enrollment)).toNot(beNil())
            }

            it("should return authentication with http url") {
                expect(Guardian.authentication(forDomain: "https://samples.guardian.auth0.com", device: enrollment)).toNot(beNil())
            }
        }

        describe("authentication(url:)") {

            let enrollment = EnrolledDevice(id: "ID", userId: "USER_ID", deviceToken: "TOKEN", notificationToken: "TOKEN", signingKey: try! DataRSAPrivateKey.new())

            it("should return authentication with http url") {
                expect(Guardian.authentication(url: URL(string: "https://samples.guardian.auth0.com")!, device: enrollment)).toNot(beNil())
            }
        }

        describe("enroll(forDomain:, withUri:, notificationToken:)") {

            let keys = Keys.shared

            var signingKey: SigningKey!
            var verificationKey: VerificationKey!

            beforeEach {
                signingKey = try! DataRSAPrivateKey(data: keys.privateKey)
                verificationKey = try! signingKey.verificationKey()

                stub(condition: isMobileEnroll(baseUrl: ValidURL)
                    && hasTicketAuth(ValidTransactionId)
                    && hasAtLeast([
                        "identifier": UIDevice.current.identifierForVendor!.uuidString,
                        "name": UIDevice.current.name
                        ])
                    && hasField("push_credentials", withParameters: [
                        "service": ValidNotificationService,
                        "token": ValidNotificationToken
                        ])
                    && hasField("public_key", withParameters: [
                        "alg": keys.jwk.algorithm,
                        "e": keys.jwk.exponent,
                        "use": keys.jwk.usage,
                        "kty": keys.jwk.keyType,
                        "n": keys.jwk.modulus
                        ])) { _ in
                            return enrollResponse(enrollmentId: ValidEnrollmentId,
                                                  url: ValidURL.absoluteString,
                                                  userId: ValidUserId,
                                                  issuer: ValidIssuer,
                                                  token: ValidEnrollmentToken,
                                                  totpSecret: ValidBase32Secret,
                                                  totpAlgorithm: ValidAlgorithm,
                                                  totpDigits: ValidDigits,
                                                  totpPeriod: ValidPeriod)
                    }.name = "Valid enrollment"
            }

            it("should succeed when enrollmentUri is valid") {
                waitUntil(timeout: Timeout) { done in
                    let uri = enrollmentUri(withTransactionId: ValidTransactionId, baseUrl: ValidURL.absoluteString, enrollmentId: ValidEnrollmentId, issuer: ValidIssuer, user: ValidUser, secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod)
                    let signingKey = try! DataRSAPrivateKey(data: keys.privateKey)
                    let verificationKey = try! signingKey.verificationKey()
                    Guardian
                        .enroll(forDomain: Domain, usingUri: uri, notificationToken: ValidNotificationToken, signingKey: signingKey, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(haveEnrollment(withBaseUrl: ValidURL, enrollmentId: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, userId: ValidUserId, signingKey: signingKey, base32Secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod))
                            done()
                    }
                }
            }

            it("should succeed when enrollmentTicket is valid") {
                waitUntil(timeout: Timeout) { done in
                    Guardian
                        .enroll(forDomain: Domain, usingTicket: ValidTransactionId, notificationToken: ValidNotificationToken, signingKey: signingKey, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(haveEnrollment(withBaseUrl: ValidURL, enrollmentId: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, userId: ValidUserId, signingKey: signingKey, base32Secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod))
                            done()
                    }
                }
            }

            it("should fail when enrollmentUri is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollmentUri = "someInvalidEnrollmentUri"
                    Guardian
                        .enroll(forDomain: Domain, usingUri: enrollmentUri, notificationToken: ValidNotificationToken, signingKey: signingKey, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid.enrollment_uri"))
                            done()
                    }
                }
            }

            it("should fail when public key is invalid") {
                waitUntil(timeout: Timeout) { done in
                    Guardian
                        .enroll(forDomain: Domain, usingTicket: ValidTransactionId, notificationToken: ValidNotificationToken, signingKey: try! DataRSAPrivateKey.new(), verificationKey: NoJWKKey())
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid_jwk"))
                            done()
                    }
                }
            }

            it("should fail when enrollment transaction is invalid") {
                stub(condition: isMobileEnroll(baseUrl: ValidURL)
                    && !hasTicketAuth(ValidTransactionId)) { _ in
                        return errorResponse(statusCode: 404, errorCode: "enrollment_transaction_not_found", message: "Not found")
                    }.name = "Enrollment transaction not found"
                waitUntil(timeout: Timeout) { done in
                    Guardian
                        .enroll(forDomain: Domain, usingTicket: "someInvalidTransactionId", notificationToken: ValidNotificationToken, signingKey: signingKey, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "enrollment_transaction_not_found"))
                            done()
                    }
                }
            }

            it("should fail when enrollment transaction is valid but response is invalid") {
                stub(condition: isMobileEnroll(baseUrl: ValidURL)
                    && hasTicketAuth(ValidTransactionId)) { _ in
                        let json = [
                            "notTheRequiredField": "someValue",
                            ]
                        return OHHTTPStubsResponse(jsonObject: json, statusCode: 200, headers: ["Content-Type": "application/json"])
                    }.name = "Invalid enroll response"
                waitUntil(timeout: Timeout) { done in
                    Guardian
                        .enroll(forDomain: Domain, usingTicket: ValidTransactionId, notificationToken: ValidNotificationToken, signingKey: signingKey, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(beFailure())
                            done()
                    }
                }
            }
        }

        describe("enroll(url:, session:, withUri:, notificationToken:)") {

            let keys = Keys.shared

            var signingKey: SigningKey!
            var verificationKey: VerificationKey!

            beforeEach {
                signingKey = try! DataRSAPrivateKey(data: keys.privateKey)
                verificationKey = try! signingKey.verificationKey()
                stub(condition: isMobileEnroll(baseUrl: ValidURL)
                    && hasTicketAuth(ValidTransactionId)
                    && hasAtLeast([
                        "identifier": UIDevice.current.identifierForVendor!.uuidString,
                        "name": UIDevice.current.name
                        ])
                    && hasField("push_credentials", withParameters: [
                        "service": ValidNotificationService,
                        "token": ValidNotificationToken
                        ])
                    && hasField("public_key", withParameters: [
                        "alg": keys.jwk.algorithm,
                        "e": keys.jwk.exponent,
                        "use": keys.jwk.usage,
                        "kty": keys.jwk.keyType,
                        "n": keys.jwk.modulus
                        ])) { _ in
                            return enrollResponse(enrollmentId: ValidEnrollmentId,
                                                  url: ValidURL.absoluteString,
                                                  userId: ValidUserId,
                                                  issuer: ValidIssuer,
                                                  token: ValidEnrollmentToken,
                                                  totpSecret: ValidBase32Secret,
                                                  totpAlgorithm: ValidAlgorithm,
                                                  totpDigits: ValidDigits,
                                                  totpPeriod: ValidPeriod)
                    }.name = "Valid enrollment"
            }

            it("should succeed when enrollmentUri is valid") {
                waitUntil(timeout: Timeout) { done in
                    let uri = enrollmentUri(withTransactionId: ValidTransactionId, baseUrl: ValidURL.absoluteString, enrollmentId: ValidEnrollmentId, issuer: ValidIssuer, user: ValidUser, secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod)
                    Guardian
                        .enroll(url: ValidURL, usingUri: uri, notificationToken: ValidNotificationToken, signingKey: signingKey, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(haveEnrollment(withBaseUrl: ValidURL, enrollmentId: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, userId: ValidUserId, signingKey: signingKey, base32Secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod))
                            done()
                    }
                }
            }

            it("should succeed when enrollmentTicket is valid") {
                waitUntil(timeout: Timeout) { done in
                    Guardian
                        .enroll(url: ValidURL, usingTicket: ValidTransactionId, notificationToken: ValidNotificationToken, signingKey: signingKey, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(haveEnrollment(withBaseUrl: ValidURL, enrollmentId: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, userId: ValidUserId, signingKey: signingKey, base32Secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod))
                            done()
                    }
                }
            }

            it("should fail when enrollmentUri is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollmentUri = "someInvalidEnrollmentUri"
                    Guardian
                        .enroll(url: ValidURL, usingUri: enrollmentUri, notificationToken: ValidNotificationToken, signingKey: signingKey, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid.enrollment_uri"))
                            done()
                    }
                }
            }

            it("should fail when public key lacks JWK") {
                waitUntil(timeout: Timeout) { done in
                    Guardian
                        .enroll(url: ValidURL, usingTicket: ValidTransactionId, notificationToken: ValidNotificationToken, signingKey: try! DataRSAPrivateKey.new(), verificationKey: NoJWKKey())
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid_jwk"))
                            done()
                    }
                }
            }

            it("should fail when enrollment transaction is invalid") {
                stub(condition: isMobileEnroll(baseUrl: ValidURL)
                    && !hasTicketAuth(ValidTransactionId)) { _ in
                        return errorResponse(statusCode: 404, errorCode: "enrollment_transaction_not_found", message: "Not found")
                    }.name = "Enrollment transaction not found"
                waitUntil(timeout: Timeout) { done in
                    Guardian
                        .enroll(url: ValidURL, usingTicket: "someInvalidTransactionId", notificationToken: ValidNotificationToken, signingKey: signingKey, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "enrollment_transaction_not_found"))
                            done()
                    }
                }
            }

            it("should fail when enrollment transaction is valid but response is invalid") {
                stub(condition: isMobileEnroll(baseUrl: ValidURL)
                    && hasTicketAuth(ValidTransactionId)) { _ in
                        let json = [
                            "notTheRequiredField": "someValue",
                            ]
                        return OHHTTPStubsResponse(jsonObject: json, statusCode: 200, headers: ["Content-Type": "application/json"])
                    }.name = "Invalid enroll response"
                waitUntil(timeout: Timeout) { done in
                    Guardian
                        .enroll(url: ValidURL, usingTicket: ValidTransactionId, notificationToken: ValidNotificationToken, signingKey: signingKey, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(beFailure())
                            done()
                    }
                }
            }
        }
    }
}

struct NoJWKKey: VerificationKey {
    let jwk: RSAPublicJWK? = nil
}

func enrollmentUri(withTransactionId transactionId: String, baseUrl: String, enrollmentId: String, issuer: String, user: String, secret: String, algorithm: HMACAlgorithm, digits: Int, period: Int) -> String {
    return "otpauth://totp/\(issuer):\(user)?secret=\(secret)&issuer=\(issuer)&enrollment_tx_id=\(transactionId)&id=\(enrollmentId)&algorithm=\(algorithm.rawValue)&digits=\(digits)&period=\(period)&base_url=\(baseUrl)"
}
