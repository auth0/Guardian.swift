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

private let Domain = "tenant.guardian.auth0.com"
private let Timeout: NSTimeInterval = 2

private let ValidURL = NSURL(string: "https://\(Domain)/")!
private let ValidTransactionId = "aValidTransactionId"
private let ValidEnrollmentId = "aValidEnrollmentId"
private let ValidEnrollmentToken = "aValidEnrollmentToken"
private let ValidNotificationToken = "aValidNotificationToken"
private let ValidIssuer = "aValidIssuer"
private let ValidUser = "aValidUser"
private let ValidBase32Secret = "aValidBase32Secret"
private let InvalidBase32Secret = "anInvalidBase32Secret!?"
private let ValidAlgorithm = "SHA1"
private let ValidDigits = 7
private let ValidPeriod = 29
private let ValidTransactionToken = "aValidTransactionToken"
private let ValidOTPCode = "aValidOTPCode"
private let ValidOTPCodeWithRejectReason = "aValidOTPCodeWithRejectReason"
private let RejectReason = "aRejectReason"

class GuardianSpec: QuickSpec {
    
    override func spec() {
        
        let guardian = _Guardian(baseUrl: ValidURL, session: NSURLSession.sharedSession())
        
        beforeEach {
            stub({ _ in return true }) { _ in
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

            it("should return api with domain and URLSession") {
                let session = NSURLSession(configuration: .ephemeralSessionConfiguration())
                expect(Guardian.api(forDomain: "samples.guardian.auth0.com", session: session)).toNot(beNil())
            }

        }

        describe("enroll") {
            
            beforeEach {
                stub(isEnrollmentInfo(domain: Domain)
                    && hasNoneOf(["enrollment_tx_id": ValidTransactionId])) { _ in
                        return errorResponse(statusCode: 404, errorCode: "enrollment_transaction_not_found", message: "Not found")
                    }.name = "Enrollment transaction not found"
                stub(isEnrollmentInfo(domain: Domain)
                    && hasAtLeast(["enrollment_tx_id": ValidTransactionId])) { _ in
                        return enrollmentInfoResponse(withDeviceAccountToken: ValidEnrollmentToken)
                    }.name = "Valid enrollment info"
                stub(isUpdateEnrollment(domain: Domain)) { _ in
                    return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(isUpdateEnrollment(domain: Domain)
                    && hasBearerToken(ValidEnrollmentToken)) { _ in
                        return errorResponse(statusCode: 404, errorCode: "enrollment_not_found", message: "Enrollment not found")
                    }.name = "Enrollment not found"
                stub(isUpdateEnrollment(domain: Domain, enrollmentId: ValidEnrollmentId)
                    && hasBearerToken(ValidEnrollmentToken)) { req in
                        let payload = req.a0_payload
                        let pushCredentials = payload?["push_credentials"] as? [String: String]
                        return enrollmentResponse(enrollmentId: ValidEnrollmentId, deviceIdentifier: payload?["identifier"] as? String, name: payload?["name"] as? String, service: pushCredentials?["service"], notificationToken: pushCredentials?["token"])
                    }.name = "Valid updated enrollment"
            }
            
            it("should succeed when enrollmentUri is valid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollmentUri = getEnrollmentUri(withTransactionId: ValidTransactionId, baseUrl: ValidURL.absoluteString!, enrollmentId: ValidEnrollmentId, issuer: ValidIssuer, user: ValidUser, secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod)
                    guardian
                        .enroll(withUri: enrollmentUri, notificationToken: ValidNotificationToken)
                        .start { result in
                            expect(result).to(haveEnrollment(withBaseUrl: ValidURL, enrollmentId: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod))
                            done()
                    }
                }
            }

            it("should fail when enrollmentUri is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollmentUri = "someInvalidEnrollmentUri"
                    guardian
                        .enroll(withUri: enrollmentUri, notificationToken: ValidNotificationToken)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid_enrollment_uri"))
                            done()
                    }
                }
            }

            it("should fail when enrollment transaction is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollmentUri = getEnrollmentUri(withTransactionId: "someInvalidTransactionId", baseUrl: ValidURL.absoluteString!, enrollmentId: ValidEnrollmentId, issuer: ValidIssuer, user: ValidUser, secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod)
                    guardian
                        .enroll(withUri: enrollmentUri, notificationToken: ValidNotificationToken)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "enrollment_transaction_not_found"))
                            done()
                    }
                }
            }

            it("should fail when enrollment transaction is valid but response is invalid") {
                stub(isEnrollmentInfo(domain: Domain)
                    && hasAtLeast(["enrollment_tx_id": ValidTransactionId])) { _ in
                        let json = [
                            "notTheRequiredField": "someValue",
                            ]
                        return OHHTTPStubsResponse(JSONObject: json, statusCode: 200, headers: ["Content-Type": "application/json"])
                    }.name = "Invalid enrollment info"
                waitUntil(timeout: Timeout) { done in
                    let enrollmentUri = getEnrollmentUri(withTransactionId: ValidTransactionId, baseUrl: ValidURL.absoluteString!, enrollmentId: ValidEnrollmentId, issuer: ValidIssuer, user: ValidUser, secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod)
                    guardian
                        .enroll(withUri: enrollmentUri, notificationToken: ValidNotificationToken)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid_response"))
                            done()
                    }
                }
            }

            it("should fail when update enrollment fails") {
                stub(isUpdateEnrollment(domain: Domain)) { _ in
                        return errorResponse(statusCode: 404, errorCode: "some_unknown_error", message: "Enrollment not found")
                    }.name = "Enrollment not found"
                waitUntil(timeout: Timeout) { done in
                    let enrollmentUri = getEnrollmentUri(withTransactionId: ValidTransactionId, baseUrl: ValidURL.absoluteString!, enrollmentId: ValidEnrollmentId, issuer: ValidIssuer, user: ValidUser, secret: ValidBase32Secret, algorithm: ValidAlgorithm, digits: ValidDigits, period: ValidPeriod)
                    guardian
                        .enroll(withUri: enrollmentUri, notificationToken: ValidNotificationToken)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "some_unknown_error"))
                            done()
                    }
                }
            }
        }

        describe("unenroll") {

            beforeEach {
                stub(isDeleteEnrollment(domain: Domain)) { _ in
                    return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(isDeleteEnrollment(domain: Domain)
                    && hasBearerToken(ValidEnrollmentToken)) { _ in
                        return errorResponse(statusCode: 404, errorCode: "enrollment_not_found", message: "Enrollment not found")
                    }.name = "Enrollment not found"
                stub(isDeleteEnrollment(domain: Domain, enrollmentId: ValidEnrollmentId)
                    && hasBearerToken(ValidEnrollmentToken)) { _ in
                        return successResponse()
                    }.name = "Valid delete enrollment"

            }

            it("should succeed when enrollment is valid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret)
                    guardian
                        .delete(enrollment: enrollment)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when enrollment is not found") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: "someInvalidEnrollmentId", deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret)
                    guardian
                        .delete(enrollment: enrollment)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "enrollment_not_found"))
                            done()
                    }
                }
            }

            it("should fail when enrollment token is not valid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: "someInvalidEnrollmentToken", notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret)
                    guardian
                        .delete(enrollment: enrollment)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }
        }

        describe("allow") {

            beforeEach {
                stub(isVerifyOTP(domain: Domain)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(isVerifyOTP(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasAtLeast(["type": "push_notification"])) { _ in
                        return errorResponse(statusCode: 401, errorCode: "invalid_otp", message: "Invalid OTP code")
                    }.name = "Invalid OTP code"
                stub(isVerifyOTP(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasAtLeast(["code": ValidOTPCode, "type": "push_notification"])) { _ in
                        return successResponse()
                    }.name = "Valid verify-otp"
            }

            it("should succeed when notification and enrollment is valid") {
                let fixedOtpGuardian = _Guardian(baseUrl: ValidURL, codeGenerator: MockCodeGenerator(otpCode: ValidOTPCode))
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret)
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, startedAt: NSDate(), source: nil, location: nil)
                    fixedOtpGuardian
                        .allow(notification: notification, enrollment: enrollment)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when otp is not valid") {
                let fixedOtpGuardian = _Guardian(baseUrl: ValidURL, codeGenerator: MockCodeGenerator(otpCode: "someInvalidOTPCode"))
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret)
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, startedAt: NSDate(), source: nil, location: nil)
                    fixedOtpGuardian
                        .allow(notification: notification, enrollment: enrollment)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_otp"))
                            done()
                    }
                }
            }

            it("should fail when transaction token is not valid") {
                let fixedOtpGuardian = _Guardian(baseUrl: ValidURL, codeGenerator: MockCodeGenerator(otpCode: ValidOTPCode))
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret)
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: "someInvalidTransactionToken", startedAt: NSDate(), source: nil, location: nil)
                    fixedOtpGuardian
                        .allow(notification: notification, enrollment: enrollment)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when enrollment secret is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: InvalidBase32Secret)
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, startedAt: NSDate(), source: nil, location: nil)
                    guardian
                        .allow(notification: notification, enrollment: enrollment)
                        .start { result in
                            expect(result).to(haveError(CodeGeneratorError.InvalidSecret))
                            done()
                    }
                }
            }

            it("should fail when enrollment algorithm is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret, algorithm: "anInvalidAlgorithm")
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, startedAt: NSDate(), source: nil, location: nil)
                    guardian
                        .allow(notification: notification, enrollment: enrollment)
                        .start { result in
                            expect(result).to(haveError(CodeGeneratorError.InvalidAlgorithm("anInvalidAlgorithm")))
                            done()
                    }
                }
            }
        }

        describe("reject") {

            beforeEach {
                stub(isRejectLogin(domain: Domain)) { _ in
                    return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(isRejectLogin(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)) { _ in
                        return errorResponse(statusCode: 401, errorCode: "invalid_otp", message: "Invalid OTP code")
                    }.name = "Invalid OTP code"
                stub(isRejectLogin(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasAtLeast(["code": ValidOTPCodeWithRejectReason, "reason": RejectReason])) { _ in
                        return successResponse()
                    }.name = "Valid reject-login with reason"
                stub(isRejectLogin(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasAtLeast(["code": ValidOTPCode])
                    && hasNoneOf(["reason"])) { _ in
                        return successResponse()
                    }.name = "Valid reject-login without reason"
            }

            it("without reason should succeed when notification and enrollment is valid") {
                let fixedOtpGuardian = _Guardian(baseUrl: ValidURL, codeGenerator: MockCodeGenerator(otpCode: ValidOTPCode))
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret)
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, startedAt: NSDate(), source: nil, location: nil)
                    fixedOtpGuardian
                        .reject(notification: notification, enrollment: enrollment)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("with reason should succeed when notification and enrollment is valid") {
                let fixedOtpGuardian = _Guardian(baseUrl: ValidURL, codeGenerator: MockCodeGenerator(otpCode: ValidOTPCodeWithRejectReason))
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret)
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, startedAt: NSDate(), source: nil, location: nil)
                    fixedOtpGuardian
                        .reject(notification: notification, withReason: RejectReason, enrollment: enrollment)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when otp is not valid") {
                let fixedOtpGuardian = _Guardian(baseUrl: ValidURL, codeGenerator: MockCodeGenerator(otpCode: "someInvalidOTPCode"))
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret)
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, startedAt: NSDate(), source: nil, location: nil)
                    fixedOtpGuardian
                        .reject(notification: notification, enrollment: enrollment)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_otp"))
                            done()
                    }
                }
            }

            it("should fail when transaction token is not valid") {
                let fixedOtpGuardian = _Guardian(baseUrl: ValidURL, codeGenerator: MockCodeGenerator(otpCode: ValidOTPCode))
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret)
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: "someInvalidTransactionToken", startedAt: NSDate(), source: nil, location: nil)
                    fixedOtpGuardian
                        .reject(notification: notification, enrollment: enrollment)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when enrollment secret is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: InvalidBase32Secret)
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, startedAt: NSDate(), source: nil, location: nil)
                    guardian
                        .reject(notification: notification, withReason: RejectReason, enrollment: enrollment)
                        .start { result in
                            expect(result).to(haveError(CodeGeneratorError.InvalidSecret))
                            done()
                    }
                }
            }

            it("should fail when enrollment algorithm is invalid") {
                waitUntil(timeout: Timeout) { done in
                    let enrollment = Enrollment(baseURL: ValidURL, id: ValidEnrollmentId, deviceToken: ValidEnrollmentToken, notificationToken: ValidNotificationToken, issuer: ValidIssuer, user: ValidUser, base32Secret: ValidBase32Secret, algorithm: "anInvalidAlgorithm")
                    let notification = Notification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, startedAt: NSDate(), source: nil, location: nil)
                    guardian
                        .reject(notification: notification, withReason: RejectReason, enrollment: enrollment)
                        .start { result in
                            expect(result).to(haveError(CodeGeneratorError.InvalidAlgorithm("anInvalidAlgorithm")))
                            done()
                    }
                }
            }
        }
    }
}

func getEnrollmentUri(withTransactionId transactionId: String, baseUrl: String, enrollmentId: String, issuer: String, user: String, secret: String, algorithm: String, digits: Int, period: Int) -> String {
    return "otpauth://totp/\(issuer):\(user)?secret=\(secret)&issuer=\(issuer)&enrollment_tx_id=\(transactionId)&id=\(enrollmentId)&algorithm=\(algorithm)&digits=\(digits)&period=\(period)&base_url=\(baseUrl)"
}

struct MockCodeGenerator: CodeGenerator {
    let otpCode: String
    func generate(forEnrollment _: Enrollment) throws -> String {
        return otpCode
    }
}

extension CodeGeneratorError: Equatable {}

public func ==(lhs: CodeGeneratorError, rhs: CodeGeneratorError) -> Bool {
    switch (lhs, rhs) {
    case (.InvalidAlgorithm(let l), .InvalidAlgorithm(let r)):
        return l == r
    case (.InvalidSecret, .InvalidSecret):
        return true
    default:
        return false
    }
}

