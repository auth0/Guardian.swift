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

@testable import Guardian

class AuthenticationSpec: QuickSpec {

    override class func spec() {

        var signingKey: SigningKey!
        var device: MockAuthenticationDevice!

        beforeEach {
            MockURLProtocol.startInterceptingRequests()
            MockURLProtocol.stub(
                name: "YOU SHALL NOT PASS!",
                condition: { _ in return true },
                error: NSError(domain: "com.auth0", code: -99999, userInfo: nil)
            )
            signingKey = try! DataRSAPrivateKey.new()
            device = MockAuthenticationDevice(localIdentifier: UIDevice.current.identifierForVendor!.uuidString, signingKey: signingKey)
        }

        afterEach {
            MockURLProtocol.stopInterceptingRequests()
        }

        describe("allow with RSA") {

            beforeEach {
                MockURLProtocol.stub(
                    name:"Missing authentication",
                    condition: isResolveTransaction(baseUrl: ValidURL),
                    response: { _ in
                        errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }
                )
                MockURLProtocol.stub(
                    name: "Checking challenge_response",
                    condition: 
                        isResolveTransaction(baseUrl: ValidURL)
                        && hasBearerToken(ValidTransactionToken),
                    response: { req in
                        if checkJWT(request: req, accepted: true, verificationKey: device.verificationKey) {
                            return successResponse()
                        }
                        return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challenge_response")
                    }
                )
            }

            it("should succeed when notification and enrollment is valid") {
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: device)
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when transaction token is not valid") {
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: "someInvalidTransactionToken", challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: device)
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when challenge is invalid") {
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: "anInvalidNotificationChallenge", startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: device)
                        .allow(notification: notification)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when enrollment signing key is not correct") {
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                let anotherDevice = MockAuthenticationDevice(localIdentifier: UUID().uuidString, signingKey: try! DataRSAPrivateKey.new())
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: anotherDevice)
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
                MockURLProtocol.stub(
                    name: "Missing authentication",
                    condition: isResolveTransaction(baseUrl: ValidURL),
                    response: { _ in
                        errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                    }
                )
                MockURLProtocol.stub(
                    name: "Checking challenge_response",
                    condition:
                        isResolveTransaction(baseUrl: ValidURL)
                        && hasBearerToken(ValidTransactionToken),
                    response: { req in
                        if checkJWT(request: req, accepted: false, reason: RejectReason, verificationKey: device.verificationKey) {
                            return successResponse()
                        }
                        return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challenge_response")
                    }
                )
            }

            it("without reason should succeed when notification and enrollment is valid") {
                MockURLProtocol.stub(
                    name: "Checking challenge_response",
                    condition: 
                        isResolveTransaction(baseUrl: ValidURL)
                        && hasBearerToken(ValidTransactionToken),
                    response: { req in
                        if checkJWT(request: req, accepted: false, verificationKey: device.verificationKey) {
                            return successResponse()
                        }
                        return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challenge_response")
                    }
                )

                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: device)
                        .reject(notification: notification)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("with reason should succeed when notification and enrollment is valid") {
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: device)
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when transaction token is not valid") {
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: "someInvalidTransactionToken", challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: device)
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when challenge is invalid") {
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: "anInvalidNotificationChallenge", startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: device)
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }

            it("should fail when enrollment signing key is not correct") {
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                let anotherDevice = MockAuthenticationDevice(localIdentifier: UUID().uuidString, signingKey: try! DataRSAPrivateKey.new())
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: anotherDevice)
                        .reject(notification: notification, withReason: RejectReason)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                            done()
                    }
                }
            }
        }

        describe("handleAction") {

            it("should allow when identifier is com.auth0.notification.authentication.accept") {
                MockURLProtocol.stub(
                    name: "Checking challenge_response",
                    condition:
                        isResolveTransaction(baseUrl: ValidURL)
                        && hasBearerToken(ValidTransactionToken),
                    response: { req in
                        if checkJWT(request: req, accepted: true, verificationKey: device.verificationKey) {
                            return successResponse()
                        }
                        return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challenge_response")
                    }
                )
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: device)
                        .handleAction(withIdentifier: "com.auth0.notification.authentication.accept", notification: notification)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should reject when identifier is com.auth0.notification.authentication.reject") {
                MockURLProtocol.stub(
                    name: "Checking challenge_response",
                    condition:
                        isResolveTransaction(baseUrl: ValidURL)
                        && hasBearerToken(ValidTransactionToken),
                    response: { req in
                        if checkJWT(request: req, accepted: false, verificationKey: device.verificationKey) {
                            return successResponse()
                        }
                        return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challenge_response")
                    }
                )
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: device)
                        .handleAction(withIdentifier: "com.auth0.notification.authentication.reject", notification: notification)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }

            it("should fail when identifier is not valid") {
                let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                waitUntil(timeout: Timeout) { done in
                    Guardian.authentication(forDomain: Domain, device: device)
                        .handleAction(withIdentifier: "com.auth0.notification.authentication.something", notification: notification)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid.notification_action_identifier"))
                            done()
                    }
                }
            }
        }

        describe("using url") {

            describe("allow with RSA") {

                beforeEach {
                    MockURLProtocol.stub(
                        name: "Missing authentication",
                        condition: isResolveTransaction(baseUrl: ValidURL),
                        response : { _ in
                            errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                        }
                    )
                    MockURLProtocol.stub(
                        name: "Checking challenge_response",
                        condition: 
                            isResolveTransaction(baseUrl: ValidURL)
                            && hasBearerToken(ValidTransactionToken),
                        response: { req in
                            if checkJWT(request: req, accepted: true, verificationKey: device.verificationKey) {
                                return successResponse()
                            }
                            return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challenge_response")
                        }
                    )
                }

                it("should succeed when notification and enrollment is valid") {
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: device)
                            .allow(notification: notification)
                            .start { result in
                                expect(result).to(beSuccess())
                                done()
                        }
                    }
                }

                it("should fail when transaction token is not valid") {
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: "someInvalidTransactionToken", challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: device)
                            .allow(notification: notification)
                            .start { result in
                                expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                                done()
                        }
                    }
                }

                it("should fail when challenge is invalid") {
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: "anInvalidNotificationChallenge", startedAt: Date(), source: nil, location: nil)
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: device)
                            .allow(notification: notification)
                            .start { result in
                                expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                                done()
                        }
                    }
                }

                it("should fail when enrollment signing key is not correct") {
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    let anotherDevice = MockAuthenticationDevice(localIdentifier: UUID().uuidString, signingKey: try! DataRSAPrivateKey.new())
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: anotherDevice)
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
                    MockURLProtocol.stub(
                        name: "Missing authentication",
                        condition: isResolveTransaction(baseUrl: ValidURL),
                        response: { _ in
                            errorResponse(statusCode: 404, errorCode: "invalid_token", message: "Invalid transaction token")
                        }
                    )
                    MockURLProtocol.stub(
                        name: "Checking challenge_response",
                        condition:
                            isResolveTransaction(baseUrl: ValidURL)
                            && hasBearerToken(ValidTransactionToken),
                        response: { req in
                            if checkJWT(request: req, accepted: false, reason: RejectReason, verificationKey: device.verificationKey) {
                                return successResponse()
                            }
                            return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challenge_response")
                        }
                    )
                }

                it("without reason should succeed when notification and enrollment is valid") {
                    MockURLProtocol.stub(
                        name: "Checking challenge_response",
                        condition:
                            isResolveTransaction(baseUrl: ValidURL)
                            && hasBearerToken(ValidTransactionToken),
                        response: { req in
                            if checkJWT(request: req, accepted: false, verificationKey: device.verificationKey) {
                                return successResponse()
                            }
                            return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challenge_response")
                        }
                    )

                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: device)
                            .reject(notification: notification)
                            .start { result in
                                expect(result).to(beSuccess())
                                done()
                        }
                    }
                }

                it("with reason should succeed when notification and enrollment is valid") {
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: device)
                            .reject(notification: notification, withReason: RejectReason)
                            .start { result in
                                expect(result).to(beSuccess())
                                done()
                        }
                    }
                }

                it("should fail when transaction token is not valid") {
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: "someInvalidTransactionToken", challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: device)
                            .reject(notification: notification, withReason: RejectReason)
                            .start { result in
                                expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                                done()
                        }
                    }
                }

                it("should fail when challenge is invalid") {
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: "anInvalidNotificationChallenge", startedAt: Date(), source: nil, location: nil)
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: device)
                            .reject(notification: notification, withReason: RejectReason)
                            .start { result in
                                expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                                done()
                        }
                    }
                }

                it("should fail when enrollment signing key is not correct") {
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    let anotherDevice = MockAuthenticationDevice(localIdentifier: UUID().uuidString, signingKey: try! DataRSAPrivateKey.new())
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: anotherDevice)
                            .reject(notification: notification, withReason: RejectReason)
                            .start { result in
                                expect(result).to(haveGuardianError(withErrorCode: "invalid_token"))
                                done()
                        }
                    }
                }
            }

            describe("handleAction") {

                it("should allow when identifier is com.auth0.notification.authentication.accept") {
                    MockURLProtocol.stub(
                        name: "Checking challenge_response",
                        condition:
                            isResolveTransaction(baseUrl: ValidURL)
                            && hasBearerToken(ValidTransactionToken),
                        response: { req in
                            if checkJWT(request: req, accepted: true, verificationKey: device.verificationKey) {
                                return successResponse()
                            }
                            return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challenge_response")
                        }
                    )
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: device)
                            .handleAction(withIdentifier: "com.auth0.notification.authentication.accept", notification: notification)
                            .start { result in
                                expect(result).to(beSuccess())
                                done()
                        }
                    }
                }

                it("should reject when identifier is com.auth0.notification.authentication.reject") {
                    MockURLProtocol.stub(
                        name: "Checking challenge_response",
                        condition:
                            isResolveTransaction(baseUrl: ValidURL)
                            && hasBearerToken(ValidTransactionToken),
                        response: { req in
                            if checkJWT(request: req, accepted: false, verificationKey: device.verificationKey) {
                                return successResponse()
                            }
                            return errorResponse(statusCode: 401, errorCode: "invalid_token", message: "Invalid challenge_response")
                        }
                    )
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: device)
                            .handleAction(withIdentifier: "com.auth0.notification.authentication.reject", notification: notification)
                            .start { result in
                                expect(result).to(beSuccess())
                                done()
                        }
                    }
                }

                it("should fail when identifier is not valid") {
                    let notification = AuthenticationNotification(domain: Domain, enrollmentId: ValidEnrollmentId, transactionToken: ValidTransactionToken, challenge: ValidNotificationChallenge, startedAt: Date(), source: nil, location: nil)
                    waitUntil(timeout: Timeout) { done in
                        Guardian.authentication(url: ValidURL, device: device)
                            .handleAction(withIdentifier: "com.auth0.notification.authentication.something", notification: notification)
                            .start { result in
                                expect(result).to(haveGuardianError(withErrorCode: "a0.guardian.internal.invalid.notification_action_identifier"))
                                done()
                        }
                    }
                }
            }

        }
    }
}

struct MockAuthenticationDevice: AuthenticationDevice {
    let localIdentifier: String
    let signingKey: SigningKey

    var verificationKey: AsymmetricPublicKey {
        return try! AsymmetricPublicKey(privateKey: self.signingKey.secKey)
    }
}

func checkJWT(request: URLRequest, accepted: Bool, reason: String? = nil, challenge: String = ValidNotificationChallenge, verificationKey: AsymmetricPublicKey) -> Bool {
    let currentTime = Date()
    if let payload = request.a0_payload,
        let challengeResponse = payload["challenge_response"] as? String,
        let jwt: JWT<GuardianClaimSet> = try? JWT(string: challengeResponse),
        let verified = try? jwt.verify(with: verificationKey.secKey),
        verified == true,
        jwt.claimSet.audience == "https://tenant.guardian.auth0.com/also/works/in/appliance/api/resolve-transaction",
        jwt.claimSet.subject == challenge,
        jwt.claimSet.issuer == EnrolledDevice.vendorIdentifier,
        jwt.claimSet.issuedAt <= currentTime,
        jwt.claimSet.issuedAt >= currentTime.addingTimeInterval(-5),
        jwt.claimSet.expireAt <= currentTime.addingTimeInterval(30),
        jwt.claimSet.expireAt >= currentTime.addingTimeInterval(25),
        jwt.claimSet.method == "push",
        jwt.claimSet.status == accepted
    {
        if let reason = reason {
            return jwt.claimSet.reason == reason
        } else {
            return true
        }
    }
    return false
}
