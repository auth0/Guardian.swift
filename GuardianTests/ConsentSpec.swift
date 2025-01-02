// AuthenticationSpec.swift
//
// Copyright (c) 2024 Auth0 (http://auth0.com)
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

class ConsentSpec: QuickSpec {
    
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
        
        describe("Consent Url") {
            beforeEach {
                MockURLProtocol.stub(
                    name: "Valid URL",
                    condition: isGetConsent(baseUrl: ValidAuthenticationURL, consentId: ValidTransactionLinkingId),
                    response: { req in return consentResponse() }
                )
            }
            
            it("should succeed when canonical domain is passed") {
                waitUntil(timeout: Timeout) { done in
                    Guardian.consent(forDomain: "tenant.auth0.com")
                        .fetch(consentId: ValidTransactionLinkingId, notificationToken: ValidTransactionToken, signingKey: signingKey)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                        }
                }
            }
        }
        
        describe("DPoP validation") {
            beforeEach {
                MockURLProtocol.stub(
                    name: "Checking DPoP",
                    condition: isGetConsent(baseUrl: ValidAuthenticationURL, consentId: ValidTransactionLinkingId) && hasDPoPToken(ValidTransactionToken),
                    response: { req in
                        if checkDPoPAssertion(request: req, verificationKey: device.verificationKey) {
                            return consentResponse()
                        }
                        
                        return errorResponse(statusCode: 403, errorCode: "invalid_dpop_assertion", message: "Invalid DPoP Assertion")
                    }
                )
            }
            
            it("should succeed when notification and enrollment is valid") {
                waitUntil(timeout: Timeout) { done in
                    Guardian.consent(forDomain: AuthenticationDomain)
                        .fetch(consentId: ValidTransactionLinkingId, notificationToken: ValidTransactionToken, signingKey: signingKey)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                        }
                }
            }
            
            it("should fail when enrollment signing key is not correct") {
                waitUntil(timeout: Timeout) { done in
                    Guardian.consent(forDomain: AuthenticationDomain)
                        .fetch(consentId: ValidTransactionLinkingId, notificationToken: ValidTransactionToken, signingKey: try! DataRSAPrivateKey.new())
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "invalid_dpop_assertion"))
                            done()
                        }
                }
            }
        }
    }
}


func checkDPoPAssertion(request: URLRequest, verificationKey: AsymmetricPublicKey) -> Bool {
    let currentTime = Date()
    if let assertion = request.value(forHTTPHeaderField: "MFA-DPoP"),
       let jwt = try? JWT<DPoPClaimSet>(string: assertion),
       let verified = try? jwt.verify(with: verificationKey.secKey),
       verified,
       jwt.claimSet.httpMethod == "GET",
       jwt.claimSet.issuedAt <= currentTime,
       jwt.claimSet.issuedAt >= currentTime.addingTimeInterval(-5),
       !jwt.claimSet.jti.isEmpty,
       jwt.claimSet.accessTokenHash == ValidTransactionTokenShah256,
       jwt.header.algorithm == .rs256,
       jwt.header.type == "dpop+jwt",
       jwt.header.jwk == verificationKey.jwk
    {
      return true
    }
    
    return false
}
