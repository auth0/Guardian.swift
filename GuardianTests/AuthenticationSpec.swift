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

        beforeEach {
            stub(condition: { _ in return true }) { _ in
                return OHHTTPStubsResponse.init(error: NSError(domain: "com.auth0", code: -99999, userInfo: nil))
                }.name = "YOU SHALL NOT PASS!"
        }

        afterEach {
            OHHTTPStubs.removeAllStubs()
        }

        describe("allow") {

            beforeEach {
                stub(condition: isVerifyOTP(domain: Domain)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(condition: isVerifyOTP(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasOtpCode(inParameter: "code")
                    && hasAtLeast(["type": "push_notification"])) { _ in
                        return errorResponse(statusCode: 401, errorCode: "invalid_otp", message: "Invalid OTP code")
                    }.name = "Invalid OTP code"
            }

            it("should succeed when notification and enrollment is valid") {
                stub(condition: isVerifyOTP(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasOtpCode(inParameter: "code")
                    && hasAtLeast(["type": "push_notification"])) { _ in
                        return successResponse()
                    }.name = "Valid verify-otp"
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let auth = Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                waitUntil(timeout: Timeout) { done in
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    auth
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when otp is not valid") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let auth = Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                waitUntil(timeout: Timeout) { done in
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    auth
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_otp"))
                            done()
                    }
                }
            }

            it("should fail when transaction token is not valid") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let fixedOtpGuardian = Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                waitUntil(timeout: Timeout) { done in
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: "someInvalidTransactionToken", challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    fixedOtpGuardian
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when enrollment secret is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: InvalidBase32Secret)
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(haveError(GuardianError.invalidBase32Secret))
                            done()
                    }
                }
            }

            it("should fail when enrollment algorithm is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret, algorithm: "anInvalidAlgorithm")
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(haveError(GuardianError.invalidOTPAlgorithm))
                            done()
                    }
                }
            }
        }

        describe("reject") {

            beforeEach {
                stub(condition: isRejectLogin(domain: Domain)) { _ in
                    return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(condition: isRejectLogin(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)) { _ in
                        return errorResponse(statusCode: 401, errorCode: "invalid_otp", message: "Invalid OTP code")
                    }.name = "Invalid OTP code"
            }

            it("without reason should succeed when notification and enrollment is valid") {
                stub(condition: isRejectLogin(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasOtpCode(inParameter: "code")
                    && hasNoneOf(["reason"])) { _ in
                        return successResponse()
                    }.name = "Valid reject-login without reason"
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let auth = Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                waitUntil(timeout: Timeout) { done in
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    auth
                        .reject(notification: notification)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("with reason should succeed when notification and enrollment is valid") {
                stub(condition: isRejectLogin(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasOtpCode(inParameter: "code")
                    && hasAtLeast(["reason": RejectReason])) { _ in
                        return successResponse()
                    }.name = "Valid reject-login with reason"
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let auth = Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                waitUntil(timeout: Timeout) { done in
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    auth
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when otp is not valid") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let auth = Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                waitUntil(timeout: Timeout) { done in
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    auth
                        .reject(notification: notification)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_otp"))
                            done()
                    }
                }
            }

            it("should fail when transaction token is not valid") {
                let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret)
                let auth = Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                waitUntil(timeout: Timeout) { done in
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: "someInvalidTransactionToken", challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    auth
                        .reject(notification: notification)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when enrollment secret is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: InvalidBase32Secret)
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(haveError(GuardianError.invalidBase32Secret))
                            done()
                    }
                }
            }

            it("should fail when enrollment algorithm is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, signingKey: ValidRSAPrivateKey, base32Secret: ValidBase32Secret, algorithm: "anInvalidAlgorithm")
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    Guardian.authentication(forDomain: Domain, andEnrollment: enrollment)
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(haveError(GuardianError.invalidOTPAlgorithm))
                            done()
                    }
                }
            }
        }
    }
}
