// APIClientSpec.swift
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

class APIClientSpec: QuickSpec {
    
    override func spec() {
        
        let client = APIClient(baseUrl: ValidURL, session: Guardian.defaultURLSession)
        
        beforeEach {
            stub(condition: { _ in return true }) { _ in
                return OHHTTPStubsResponse.init(error: NSError(domain: "com.auth0", code: -99999, userInfo: nil))
                }.name = "YOU SHALL NOT PASS!"
        }
        
        afterEach {
            OHHTTPStubs.removeAllStubs()
        }

        describe("enroll") {

            beforeEach {
                stub(condition: isMobileEnroll(baseUrl: ValidURL)
                    && hasTicketAuth(ValidTransactionId)
                    && hasAtLeast([
                        "identifier": ValidDeviceIdentifier,
                        "name": ValidDeviceName
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
                                                  userId: ValidUserId,
                                                  issuer: ValidIssuer,
                                                  token: ValidEnrollmentToken,
                                                  totpSecret: ValidBase32Secret,
                                                  totpAlgorithm: ValidAlgorithm,
                                                  totpDigits: ValidDigits,
                                                  totpPeriod: ValidPeriod)
                    }.name = "Valid enrollment"
            }

            it("should return enroll data") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .enroll(withTicket: ValidTransactionId, identifier: ValidDeviceIdentifier, name: ValidDeviceName, notificationToken: ValidNotificationToken, publicKey: ValidRSAPublicKey)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when public key is invalid") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .enroll(withTicket: ValidTransactionId, identifier: ValidDeviceIdentifier, name: ValidDeviceName, notificationToken: ValidNotificationToken, publicKey: NonRSAPublicKey)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid_public_key"))
                            done()
                    }
                }
            }
        }

        describe("resolve-transaction") {

            beforeEach {
                stub(condition: isResolveTransaction(baseUrl: ValidURL)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(condition: isResolveTransaction(baseUrl: ValidURL)
                    && hasBearerToken(ValidTransactionToken)) { req in
                        return errorResponse(statusCode: 401, errorCode: "invalid_challenge", message: "Invalid challenge_response")
                    }.name = "Invalid challenge_response"
                stub(condition: isResolveTransaction(baseUrl: ValidURL)
                    && hasBearerToken(ValidTransactionToken)
                    && hasAtLeast([
                        "challenge_response": ValidChallengeResponse
                    ])) { req in
                        return successResponse()
                    }.name = "Valid resolve request"
            }

            it("should succeed with valid transaction and challenge response") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .resolve(transaction: ValidTransactionToken, withChallengeResponse: ValidChallengeResponse)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when transaction is invalid") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .resolve(transaction: "someInvalidTransactionToken", withChallengeResponse: ValidChallengeResponse)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when challenge_response is invalid") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .resolve(transaction: ValidTransactionToken, withChallengeResponse: "abcdefgh")
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_challenge"))
                            done()
                    }
                }
            }
        }

        describe("delete enrollment") {
            
            beforeEach {
                stub(condition: isDeleteEnrollment(baseUrl: ValidURL)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(condition: isDeleteEnrollment(baseUrl: ValidURL)
                    && hasBearerToken(ValidEnrollmentToken)) { _ in
                        return errorResponse(statusCode: 404, errorCode: "enrollment_not_found", message: "Enrollment not found")
                    }.name = "Enrollment not found"
                stub(condition: isDeleteEnrollment(baseUrl: ValidURL, enrollmentId: ValidEnrollmentId)
                    && hasBearerToken(ValidEnrollmentToken)) { _ in
                        return successResponse()
                    }.name = "Valid delete enrollment"
            }
            
            it("should delete enrollment") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .device(forEnrollmentId: ValidEnrollmentId, token: ValidEnrollmentToken)
                        .delete()
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }
            
            it("should fail with enrollment_not_found error") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .device(forEnrollmentId: "someInvalidEnrollmentId", token: ValidEnrollmentToken)
                        .delete()
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "enrollment_not_found"))
                            done()
                    }
                }
            }
            
            it("should fail with invalid_token error") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .device(forEnrollmentId: ValidEnrollmentId, token: "someInvalidEnrollmentToken")
                        .delete()
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }
        }
        
        describe("update enrollment") {
            
            beforeEach {
                stub(condition: isUpdateEnrollment(baseUrl: ValidURL)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(condition: isUpdateEnrollment(baseUrl: ValidURL)
                    && hasBearerToken(ValidEnrollmentToken)) { _ in
                        return errorResponse(statusCode: 404, errorCode: "enrollment_not_found", message: "Enrollment not found")
                    }.name = "Enrollment not found"
                stub(condition: isUpdateEnrollment(baseUrl: ValidURL, enrollmentId: ValidEnrollmentId)
                    && hasBearerToken(ValidEnrollmentToken)) { req in
                        let payload = req.a0_payload
                        let pushCredentials = payload?["push_credentials"] as? [String: String]
                        return deviceResponse(enrollmentId: ValidEnrollmentId, deviceIdentifier: payload?["identifier"] as? String, name: payload?["name"] as? String, service: pushCredentials?["service"], notificationToken: pushCredentials?["token"])
                    }.name = "Valid updated enrollment"
            }
            
            it("should update enrollment") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .device(forEnrollmentId: ValidEnrollmentId, token: ValidEnrollmentToken)
                        .update(deviceIdentifier: ValidDeviceIdentifier, name: ValidDeviceName, notificationToken: ValidNotificationToken)
                        .start { result in
                            expect(result).to(haveEnrollment(withId: ValidEnrollmentId, deviceIdentifier: ValidDeviceIdentifier, deviceName: ValidDeviceName, notificationService: ValidNotificationService, notificationToken: ValidNotificationToken))
                            done()
                    }
                }
            }
            
            it("should fail with enrollment_not_found error") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .device(forEnrollmentId: "someInvalidEnrollmentId", token: ValidEnrollmentToken)
                        .update(deviceIdentifier: "someDeviceIdentifier", name: "someName", notificationToken: "someNotificationToken")
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "enrollment_not_found"))
                            done()
                    }
                }
            }
            
            it("should fail with invalid_token error") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .device(forEnrollmentId: ValidEnrollmentId, token: "someInvalidEnrollmentToken")
                        .update(deviceIdentifier: "someDeviceIdentifier", name: "someName", notificationToken: "someNotificationToken")
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }
        }
    }
}
