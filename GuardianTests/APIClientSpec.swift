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
        
        let client = APIClient(baseUrl: ValidURL)
        let keys = Keys.shared
        let signingKey = try! DataRSAPrivateKey(data: keys.privateKey)
        let verificationKey = try! signingKey.verificationKey()
        
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
                        "alg": keys.jwk.algorithm,
                        "e": keys.jwk.exponent,
                        "use": keys.jwk.usage,
                        "kty": keys.jwk.keyType,
                        "n": keys.jwk.modulus
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
                        .enroll(withTicket: ValidTransactionId, identifier: ValidDeviceIdentifier, name: ValidDeviceName, notificationToken: ValidNotificationToken, verificationKey: verificationKey)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when public key is invalid") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .enroll(withTicket: ValidTransactionId, identifier: ValidDeviceIdentifier, name: ValidDeviceName, notificationToken: ValidNotificationToken, verificationKey: NoJWKKey())
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
                        .update(localIdentifier: ValidDeviceIdentifier, name: ValidDeviceName, notificationToken: ValidNotificationToken)
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
                        .update(localIdentifier: "someDeviceIdentifier", name: "someName", notificationToken: "someNotificationToken")
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
                        .update(localIdentifier: "someDeviceIdentifier", name: "someName", notificationToken: "someNotificationToken")
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }
        }
    }
}
