// AuthenticationSpec.swift
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

class AuthenticationSpec: QuickSpec {

    override func spec() {

        let (_, privateKey) = generateKeyPair(publicTag: UUID().uuidString,
                                                      privateTag: UUID().uuidString,
                                                      keyType: kSecAttrKeyTypeRSA,
                                                      keySize: RSAKeySize)!

        beforeEach {
            stub(condition: { _ in return true }) { _ in
                return OHHTTPStubsResponse.init(error: NSError(domain: "com.auth0", code: -99999, userInfo: nil))
                }.name = "YOU SHALL NOT PASS!"
        }

        afterEach {
            OHHTTPStubs.removeAllStubs()
        }

        describe("allow with RSA") {

            beforeEach {
                stub(condition: isResolveTransaction(domain: Domain)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(condition: isResolveTransaction(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)) { req in
                        if checkJWT(request: req, accepted: true) {
                            return successResponse()
                        }
                        return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challengeResponse")
                    }.name = "Checking challengeResponse"
            }

            it("should succeed when notification and enrollment is valid") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when transaction token is not valid") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: "someInvalidTransactionToken", challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when challenge is invalid") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: "anInvalidNotificationChallenge", startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when enrollment signing key is not correct") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: privateKey, base32Secret: ValidBase32Secret)
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }
        }

        describe("reject with RSA") {

            beforeEach {
                stub(condition: isResolveTransaction(domain: Domain)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(condition: isResolveTransaction(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)) { req in
                        if checkJWT(request: req, accepted: false, reason: RejectReason) {
                            return successResponse()
                        }
                        return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challengeResponse")
                    }.name = "Checking challengeResponse"
            }

            it("without reason should succeed when notification and enrollment is valid") {
                stub(condition: isResolveTransaction(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)) { req in
                        if checkJWT(request: req, accepted: false) {
                            return successResponse()
                        }
                        return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challengeResponse")
                    }.name = "Checking challengeResponse"

                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .reject(notification: notification)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("with reason should succeed when notification and enrollment is valid") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when transaction token is not valid") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: "someInvalidTransactionToken", challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when challenge is invalid") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: "anInvalidNotificationChallenge", startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when enrollment signing key is not correct") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: privateKey, base32Secret: ValidBase32Secret)
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }
        }
    }
}

func checkJWT(request: URLRequest, accepted: Bool, reason: String? = nil, challenge: String = ValidNotificationChallenge) -> Bool {
    let currentTime = Int(Date().timeIntervalSince1970)
    if let payload = request.a0_payload,
        let challengeResponse = payload["challengeResponse"] as? String,
        let claims = try? JWT.verify(string: challengeResponse, publicKey: ValidRSAPublicKey),
        let aud = claims["aud"] as? String,
        aud == "https://\(Domain)",
        let sub = claims["sub"] as? String,
        sub == challenge,
        let iss = claims["iss"] as? String,
        iss == Enrollment.defaultDeviceIdentifier,
        let iat = claims["iat"] as? Int,
        iat <= currentTime,
        iat >= currentTime - 5,
        let exp = claims["exp"] as? Int,
        exp <= currentTime + 30,
        exp >= currentTime + 25,
        let method = claims["auth0.guardian.method"] as? String,
        method == "push",
        let isAccepted = claims["auth0.guardian.accepted"] as? Bool,
        isAccepted == accepted
    {
        if let reason = reason {
            if let actualReason = claims["auth0.guardian.reason"] as? String {
                return actualReason == reason
            }
        } else {
            return true
        }
    }
    return false
}
