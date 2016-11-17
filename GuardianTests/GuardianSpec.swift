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
import OHHTTPStubs

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

        describe("api(forDomain:, session:)") {

            it("should return api with domain only") {
                expect(Guardian.api(forDomain: "samples.guardian.auth0.com")).toNot(beNil())
            }

            it("should return api with http url") {
                expect(Guardian.api(forDomain: "https://samples.guardian.auth0.com")).toNot(beNil())
            }

            it("should return api with domain and URLSession") {
                let session = URLSession(configuration: .ephemeral)
                expect(Guardian.api(forDomain: "samples.guardian.auth0.com", session: session)).toNot(beNil())
            }

        }

        describe("authentication(forDomain:, session:)") {

            let enrollment = Enrollment(id: "ID", deviceToken: "TOKEN", notificationToken: "TOKEN", signingKey: ValidRSAPrivateKey, base32Secret: "SECRET")

            it("should return authentication with domain only") {
                expect(Guardian.authentication(forDomain: "samples.guardian.auth0.com", andEnrollment: enrollment)).toNot(beNil())
            }

            it("should return authentication with http url") {
                expect(Guardian.authentication(forDomain: "https://samples.guardian.auth0.com", andEnrollment: enrollment)).toNot(beNil())
            }

            it("should return authentication with domain and URLSession") {
                let session = URLSession(configuration: .ephemeral)
                expect(Guardian.authentication(forDomain: "samples.guardian.auth0.com", andEnrollment: enrollment, session: session)).toNot(beNil())
            }
            
        }

        describe("enroll(forDomain:, session:, withUri:, notificationToken:)") {

            beforeEach {
                stub(condition: isMobileEnroll(domain: Domain)
                    && hasTicketAuth(ValidTransactionId)
                    && hasAtLeast([
                        "identifier": Enrollment.defaultDeviceIdentifier,
                        "name": Enrollment.defaultDeviceName
                        ])
                    && hasField("push_credentials", withParameters: [
                        "service": ValidNotificationService,
                        "token": ValidNotificationToken
                        ])
                    && hasField("public_key", withParameters: [
                        "alg": "RS256",
                        "e": "AQAB",
                        "use": "sig",
                        "kty": "RSA",
                        "n": "AKZpUNxEdyiAcvJEI-qxsGEm-96lcPh9Qtu0LWU9OY2oWhDIX_ZKsHYXbqpPyqXUYv4IcvK9X4XnuVvMqxGWxK3kARuAQgjOE-naOl5ed4FNCTTs58e7Jg32bILQqY2539MLomObKloFqAeyA5EMKv1f3pAT2dife5uN7QUz-ifaTGJlP6UCRjfY8TTbbpvFvOHfZmVptfSmq94typg4u2yUgMGRl0vTCkz35e-ox1Y7GfeIkBGQUzY6GFFXPxOct_71a6KtzXxOnYeI9HX0WYX8-hyULasv3RzTLteHIU70Bczfh7hUVGtLMBBLDY0KhZqkZAfrDA38NZm4z932-OqXJ1nVx0MiT9Kt73jy8Gp78CO7t9lJcml3vW1pW-p7swZan8Bs5u6E9Ntch1LUZitxq-f51FsCc478xDp-Yb51FFN-3MPVgW_orXfq_cuOvbQVtr2RciKHTUs4EOfxgj27X0Yzymfi33r9xtJIwUQyoXEhXN6GpKnFnQQvQtSiyhWMGTEbhN8Lu7EDJOD5E4OcZ51J_JveOtg5Y35InjQGcwcHSGzwhrbv3YUIWiXM_w6tBYCJMKC12Myb84D7mavDKhwP3iZ7LBC71kS6Fi53MkM9YIlIGb1OL_tMXDLjKkAPk7JyABITRvE_IbK1ag93UL5G2lrIAgkGNBJIx3mV"
                        ])) { _ in
                            return enrollResponse(enrollmentId: ValidEnrollmentId,
                                                  url: ValidURL.host,
                                                  user: ValidUser,
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
                        .enroll(forDomain: Domain, usingUri: uri, notificationToken: ValidNotificationToken, keyPair: ValidRSAKeyPair)
                        .start { result in
                            expect(result).to(haveEnrollment(withBaseUrl: ValidURL, enrollmentId: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod))
                            done()
                    }
                }
            }

            it("should succeed when enrollmentTicket is valid") {
                waitUntil(timeout: Timeout) { done in
                    Guardian
                        .enroll(forDomain: Domain, usingTicket: ValidTransactionId, notificationToken: ValidNotificationToken, keyPair: ValidRSAKeyPair)
                        .start { result in
                            expect(result).to(haveEnrollment(withBaseUrl: ValidURL, enrollmentId: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod))
                            done()
                    }
                }
            }

            it("should fail when enrollmentUri is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollmentUri = "someInvalidEnrollmentUri"
                    Guardian
                        .enroll(forDomain: Domain, usingUri: enrollmentUri, notificationToken: ValidNotificationToken, keyPair: ValidRSAKeyPair)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid_enrollment_uri"))
                            done()
                    }
                }
            }

            it("should fail when public key is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let uri = enrollmentUri(withTransactionId: ValidTransactionId, baseUrl: ValidURL.absoluteString, enrollmentId: ValidEnrollmentId, issuer: ValidIssuer, user: ValidUser, secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod)
                    Guardian
                        .enroll(forDomain: Domain, usingUri: uri, notificationToken: ValidNotificationToken, keyPair: RSAKeyPair(publicKey: NonRSAPublicKey, privateKey: ValidRSAPrivateKey))
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid_public_key"))
                            done()
                    }
                }
            }

            it("should fail when enrollment transaction is invalid") {
                stub(condition: isMobileEnroll(domain: Domain)
                    && !hasTicketAuth(ValidTransactionId)) { _ in
                        return errorResponse(statusCode: 404, errorCode: "enrollment_transaction_not_found", message: "Not found")
                    }.name = "Enrollment transaction not found"
                waitUntil(timeout: Timeout) { done in
                    let uri = enrollmentUri(withTransactionId: "someInvalidTransactionId", baseUrl: ValidURL.absoluteString, enrollmentId: ValidEnrollmentId, issuer: ValidIssuer, user: ValidUser, secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod)
                    Guardian
                        .enroll(forDomain: Domain, usingUri: uri, notificationToken: ValidNotificationToken, keyPair: ValidRSAKeyPair)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "enrollment_transaction_not_found"))
                            done()
                    }
                }
            }

            it("should fail when enrollment transaction is valid but response is invalid") {
                stub(condition: isMobileEnroll(domain: Domain)
                    && hasTicketAuth(ValidTransactionId)) { _ in
                        let json = [
                            "notTheRequiredField": "someValue",
                            ]
                        return OHHTTPStubsResponse(jsonObject: json, statusCode: 200, headers: ["Content-Type": "application/json"])
                    }.name = "Invalid enroll response"
                waitUntil(timeout: Timeout) { done in
                    let uri = enrollmentUri(withTransactionId: ValidTransactionId, baseUrl: ValidURL.absoluteString, enrollmentId: ValidEnrollmentId, issuer: ValidIssuer, user: ValidUser, secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod)
                    Guardian
                        .enroll(forDomain: Domain, usingUri: uri, notificationToken: ValidNotificationToken, keyPair: ValidRSAKeyPair)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid_response"))
                            done()
                    }
                }
            }
        }
    }
}

func enrollmentUri(withTransactionId transactionId: String, baseUrl: String, enrollmentId: String, issuer: String, user: String, secret: String, algorithm: String, digits: Int, period: Int) -> String {
    return "otpauth://totp/\(issuer):\(user)?secret=\(secret)&issuer=\(issuer)&enrollment_tx_id=\(transactionId)&id=\(enrollmentId)&algorithm=\(algorithm)&digits=\(digits)&period=\(period)&base_url=\(baseUrl)"
}
