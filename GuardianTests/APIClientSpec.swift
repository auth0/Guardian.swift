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

@testable import Guardian

class APIClientSpec: QuickSpec {

    override class func spec() {
        
        let client = APIClient(baseUrl: ValidURL)
        let keys = Keys.shared
        let signingKey = try! DataRSAPrivateKey(data: keys.privateKey)
        let verificationKey = try! signingKey.verificationKey()
        
        beforeEach {
            MockURLProtocol.startInterceptingRequests()
            MockURLProtocol.stub(
                name: "YOU SHALL NOT PASS!",
                condition: { _ in true },
                error: NSError(domain: "com.auth0", code: -99999, userInfo: nil)
            )
        }
        
        afterEach {
            MockURLProtocol.stopInterceptingRequests()
        }

        describe("enroll") {
            beforeEach {
                MockURLProtocol.stub(
                    name: "Valid enrollment",
                    condition: 
                        isMobileEnroll(baseUrl: ValidURL)
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
                            ]),
                    response: { _ in
                        enrollResponse(enrollmentId: ValidEnrollmentId,
                                       url: ValidURL.host,
                                       userId: ValidUserId,
                                       issuer: ValidIssuer,
                                       token: ValidEnrollmentToken,
                                       totpSecret: ValidBase32Secret,
                                       totpAlgorithm: ValidAlgorithm,
                                       totpDigits: ValidDigits,
                                       totpPeriod: ValidPeriod)
                    }
                )
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

            it("should fail when public key lacks JWK") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .enroll(withTicket: ValidTransactionId, identifier: ValidDeviceIdentifier, name: ValidDeviceName, notificationToken: ValidNotificationToken, verificationKey: NoJWKKey())
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid_jwk"))
                            done()
                    }
                }
            }
        }

        describe("resolve-transaction") {

            beforeEach {
                MockURLProtocol.stub(
                    name: "Missing authentication",
                    condition: isResolveTransaction(baseUrl: ValidURL),
                    response: { _ in
                        errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }
                )
                
                MockURLProtocol.stub(
                    name: "Invalid challenge_response",
                    condition: 
                        isResolveTransaction(baseUrl: ValidURL)
                        && hasBearerToken(ValidTransactionToken),
                    response: { _ in
                        errorResponse(statusCode: 401, errorCode: "invalid_challenge", message: "Invalid challenge_response")
                    }
                )
                
                MockURLProtocol.stub(
                    name: "Valid resolve request",
                    condition:
                        isResolveTransaction(baseUrl: ValidURL)
                        && hasBearerToken(ValidTransactionToken)
                        && hasAtLeast([
                            "challenge_response": ValidChallengeResponse
                        ]),
                    response: { _ in
                        successResponse()
                    }
                )
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

        describe("delete enrollment with opaque token") {
            
            beforeEach {
                MockURLProtocol.stub(
                    name: "Missing authentication",
                    condition: isDeleteEnrollment(baseUrl: ValidURL),
                    response: { _ in
                        errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }
                )
                MockURLProtocol.stub(
                    name: "Enrollment not found",
                    condition:
                        isDeleteEnrollment(baseUrl: ValidURL)
                        && hasBearerToken(ValidEnrollmentToken),
                    response: { _ in
                        errorResponse(statusCode: 404, errorCode: "enrollment_not_found", message: "Enrollment not found")
                    }
                )
                MockURLProtocol.stub(
                    name: "Valid delete enrollment",
                    condition:
                        isDeleteEnrollment(baseUrl: ValidURL, enrollmentId: ValidEnrollmentId)
                        && hasBearerToken(ValidEnrollmentToken),
                    response: { _ in
                        successResponse()
                    }
                )
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
        
        describe("delete enrollment with JWT token") {
            beforeEach {
                MockURLProtocol.stub(
                    name:"Valid delete enrollment",
                    condition:
                        isDeleteEnrollment(baseUrl: ValidURL, enrollmentId: ValidEnrollmentId)
                        && hasBearerJWTToken(withSub: ValidUserId,
                                             iss: ValidEnrollmentId,
                                             aud: ValidURL.appendingPathComponent(DeviceAPIClient.path).absoluteString,
                                             validFor: ValidBasicJWTDuration),
                    response: { _ in
                        successResponse()
                    }
                )
            }
            
            it("should delete enrollment") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .device(forEnrollmentId: ValidEnrollmentId, userId: ValidUserId, signingKey: signingKey)
                        .delete()
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }
        }
        
        describe("update enrollment with opaque token") {
            
            beforeEach {
                MockURLProtocol.stub(
                    name: "Missing authentication",
                    condition: isUpdateEnrollment(baseUrl: ValidURL),
                    response: { _ in
                        errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }
                )
                MockURLProtocol.stub(
                    name: "Enrollment not found",
                    condition: 
                        isUpdateEnrollment(baseUrl: ValidURL)
                        && hasBearerToken(ValidEnrollmentToken),
                    response: { _ in
                        errorResponse(statusCode: 404, errorCode: "enrollment_not_found", message: "Enrollment not found")
                    }
                )
                MockURLProtocol.stub(
                    name: "Valid updated enrollment",
                    condition: 
                        isUpdateEnrollment(baseUrl: ValidURL, enrollmentId: ValidEnrollmentId)
                        && hasBearerToken(ValidEnrollmentToken),
                    response: { req in
                        let payload = req.a0_payload
                        let pushCredentials = payload?["push_credentials"] as? [String: String]
                        return deviceResponse(enrollmentId: ValidEnrollmentId, deviceIdentifier: payload?["identifier"] as? String, name: payload?["name"] as? String, service: pushCredentials?["service"], notificationToken: pushCredentials?["token"])
                    }
                )
            }

            it("should update enrollment") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .device(forEnrollmentId: ValidEnrollmentId, token: ValidEnrollmentToken)
                        .update(localIdentifier: ValidDeviceIdentifier, name: ValidDeviceName, notificationToken: ValidNotificationToken)
                        .start { result in
                            expect(result).to(beUpdatedDevice(deviceIdentifier: ValidDeviceIdentifier, deviceName: ValidDeviceName, notificationService: ValidNotificationService, notificationToken: ValidNotificationToken))
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

        describe("update enrollment with JWT token") {
            beforeEach {
                MockURLProtocol.stub(
                    name: "Valid updated enrollment",
                    condition:
                        isUpdateEnrollment(baseUrl: ValidURL, enrollmentId: ValidEnrollmentId)
                        && hasBearerJWTToken(withSub: ValidUserId,
                                             iss: ValidEnrollmentId,
                                             aud: ValidURL.appendingPathComponent(DeviceAPIClient.path).absoluteString,
                                             validFor: ValidBasicJWTDuration),
                    response: { req in
                        let payload = req.a0_payload
                        let pushCredentials = payload?["push_credentials"] as? [String: String]
                        return deviceResponse(enrollmentId: ValidEnrollmentId, deviceIdentifier: payload?["identifier"] as? String, name: payload?["name"] as? String, service: pushCredentials?["service"], notificationToken: pushCredentials?["token"])
                    }
                )
            }
            
            it("should update enrollment") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .device(forEnrollmentId: ValidEnrollmentId, userId: ValidUserId, signingKey: signingKey)
                        .update(localIdentifier: ValidDeviceIdentifier, name: ValidDeviceName, notificationToken: ValidNotificationToken)
                        .start { result in
                            expect(result).to(beUpdatedDevice(deviceIdentifier: ValidDeviceIdentifier, deviceName: ValidDeviceName, notificationService: ValidNotificationService, notificationToken: ValidNotificationToken))
                            done()
                    }
                }
            }
        }
    }
}
