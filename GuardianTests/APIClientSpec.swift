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

private let Domain = "tenant.guardian.auth0.com"
private let Timeout: NSTimeInterval = 2

private let ValidTransactionId = "aValidTransactionId"
private let DeviceAccountToken = "someDeviceAccountToken"
private let ValidTransactionToken = "aValidTransactionToken"
private let ValidOTPCode = "aValidOTPCode"
private let RejectReason = "aRejectReason"
private let ValidEnrollmentId = "aValidEnrollmentId"
private let ValidEnrollmentToken = "aValidEnrollmentToken"
private let ValidDeviceIdentifier = "aValidDeviceIdentifier"
private let ValidDeviceName = "aValidDeviceName"
private let ValidNotificationService = "apns"
private let ValidNotificationToken = "aValidNotificationToken"

class APIClientSpec: QuickSpec {
    
    override func spec() {
        
        let client = APIClient(baseUrl: NSURL(string: "https://\(Domain)/")!, session: NSURLSession.sharedSession())
        
        beforeEach {
            stub({ _ in return true }) { _ in
                return OHHTTPStubsResponse.init(error: NSError(domain: "com.auth0", code: -99999, userInfo: nil))
                }.name = "YOU SHALL NOT PASS!"
        }
        
        afterEach {
            OHHTTPStubs.removeAllStubs()
        }
        
        describe("enrollment info") {
            
            beforeEach {
                stub(isEnrollmentInfo(domain: Domain)
                    && hasNoneOf(["enrollment_tx_id": ValidTransactionId])) { _ in
                        return errorResponse(statusCode: 404, errorCode: "enrollment_transaction_not_found", message: "Not found")
                    }.name = "Enrollment transaction not found"
                stub(isEnrollmentInfo(domain: Domain)
                    && hasAtLeast(["enrollment_tx_id": ValidTransactionId])) { _ in
                        return enrollmentInfoResponse(withDeviceAccountToken: DeviceAccountToken)
                    }.name = "Valid enrollment info"
            }
            
            it("should return enrollment token") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .enrollment(forTransactionId: ValidTransactionId)
                        .start { result in
                            expect(result).to(haveDeviceAccountToken(DeviceAccountToken))
                            done()
                    }
                }
            }
            
            it("should return enrollment_transaction_not_found error") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .enrollment(forTransactionId: "someInvalidTransactionID")
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "enrollment_transaction_not_found"))
                            done()
                    }
                }
            }
        }
        
        describe("allow authorization request") {
            
            beforeEach {
                stub(isVerifyOTP(domain: Domain)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(isVerifyOTP(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasAtLeast(["type": "push_notification"])) { _ in
                        return errorResponse(statusCode: 404, errorCode: "invalid_otp", message: "Invalid OTP code")
                    }.name = "Invalid OTP code"
                stub(isVerifyOTP(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasAtLeast(["code": ValidOTPCode, "type": "push_notification"])) { _ in
                        return successResponse()
                    }.name = "Valid verify-otp"
            }
            
            it("should allow login") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .allow(transaction: ValidTransactionToken, withCode: ValidOTPCode)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }
            
            it("should fail with invalid_otp error") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .allow(transaction: ValidTransactionToken, withCode: "someInvalidOTPCode")
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_otp"))
                            done()
                    }
                }
            }
            
            it("should fail with invalid_token error") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .allow(transaction: "someInvalidTransactionToken", withCode: ValidOTPCode)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }
        }
        
        describe("reject authorization request") {
            
            beforeEach {
                stub(isRejectLogin(domain: Domain)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(isRejectLogin(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)) { _ in
                        return errorResponse(statusCode: 404, errorCode: "invalid_otp", message: "Invalid OTP code")
                    }.name = "Invalid OTP code"
                stub(isRejectLogin(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasAtLeast(["code": ValidOTPCode, "reason": RejectReason])) { _ in
                        return successResponse()
                    }.name = "Valid reject-login with reason"
                stub(isRejectLogin(domain: Domain)
                    && hasBearerToken(ValidTransactionToken)
                    && hasAtLeast(["code": ValidOTPCode])
                    && hasNoneOf(["reason"])) { _ in
                        return successResponse()
                    }.name = "Valid reject-login without reason"
            }
            
            it("should reject login without reason") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .reject(transaction: ValidTransactionToken, withCode: ValidOTPCode)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }
            
            it("should reject login with reason") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .reject(transaction: ValidTransactionToken, withCode: ValidOTPCode, reason: RejectReason)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }
            
            it("should fail with invalid_otp error") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .reject(transaction: ValidTransactionToken, withCode: "someInvalidOTPCode")
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_otp"))
                            done()
                    }
                }
            }
            
            it("should fail with invalid_token error") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .reject(transaction: "someInvalidTransactionToken", withCode: ValidOTPCode)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }
        }
        
        describe("delete enrollment") {
            
            beforeEach {
                stub(isDeleteEnrollment(domain: Domain)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
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
                stub(isUpdateEnrollment(domain: Domain)) { _ in
                    return errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }.name = "Missing authentication"
                stub(isUpdateEnrollment(domain: Domain)
                    && hasBearerToken(ValidEnrollmentToken)) { _ in
                        return errorResponse(statusCode: 404, errorCode: "enrollment_not_found", message: "Enrollment not found")
                    }.name = "Enrollment not found"
                stub(isUpdateEnrollment(domain: Domain, enrollmentId: ValidEnrollmentId)
                    && hasBearerToken(ValidEnrollmentToken)) { req in
                        let payload = req.a0_payload
                        let pushCredentials = payload?["push_credentials"] as? [String:String]
                        return enrollmentResponse(enrollmentId: ValidEnrollmentId, deviceIdentifier: payload?["identifier"] as? String, name: payload?["name"] as? String, service: pushCredentials?["service"], notificationToken: pushCredentials?["token"])
                    }.name = "Valid updated enrollment"
            }
            
            it("should create enrollment") {
                waitUntil(timeout: Timeout) { done in
                    client
                        .device(forEnrollmentId: ValidEnrollmentId, token: ValidEnrollmentToken)
                        .create(withDeviceIdentifier: ValidDeviceIdentifier, name: ValidDeviceName, notificationToken: ValidNotificationToken)
                        .start { result in
                            expect(result).to(haveEnrollment(withId: ValidEnrollmentId, deviceIdentifier: ValidDeviceIdentifier, deviceName: ValidDeviceName, notificationService: ValidNotificationService, notificationToken: ValidNotificationToken))
                            done()
                    }
                }
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
