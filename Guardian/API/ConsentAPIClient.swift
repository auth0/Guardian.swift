// ConsentAPIClient.swift
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

import Foundation
import CryptoKit

struct ConsentAPIClient : ConsentAPI {
    static let path: String = "rich-consents"
    
    let url:URL
    let telemetryInfo: Auth0TelemetryInfo?
    let privateKey: SecKey
    let publicKey: VerificationKey
    
    init(baseUrl: URL, signingKey:SigningKey, telemetryInfo: Auth0TelemetryInfo? = nil ) {
        let url = ConsentAPIClient.constructConsentAPIUrl(baseUrl: baseUrl)
        self.url = url
        self.telemetryInfo = telemetryInfo
        self.privateKey = signingKey.secKey
        self.publicKey = try! signingKey.verificationKey()
    }
    
    func get(consentId:String, notificationToken: String) -> Request<NoContent, Consent> {
        let consentURL = self.url.appendingPathComponent(consentId)
        
        do {
            let dpopAssertion = try self.proofOfPossesion(url:consentURL, notificationToken:notificationToken)
            return Request.new(
                method: .get,
                url: consentURL,
                headers: [
                    "Authorization": "MFA-DPoP \(notificationToken)",
                    "MFA-DPoP": dpopAssertion
                ],
                telemetryInfo: self.telemetryInfo
            )
        }
        catch let error {
            return Request(method: .get, url: consentURL, error: error)
        }
    }

    private static func constructConsentAPIUrl(baseUrl: URL) -> URL {
        var consentAPIUrl = baseUrl
        
        if baseUrl.lastPathComponent == "appliance-mfa" {
            consentAPIUrl = baseUrl.deletingLastPathComponent()
        }
        
        if baseUrl.host!.components(separatedBy: ".").contains("guardian") {
            consentAPIUrl = URL(string: baseUrl.absoluteString.replacingOccurrences(of: "guardian.", with: ""))!
        }
        
        return consentAPIUrl.appendingPathComponent(ConsentAPIClient.path, isDirectory: false)
    }
    
    private func proofOfPossesion (url: URL, notificationToken:String) throws -> String {
        guard let jwk = publicKey.jwk else {
            throw GuardianError(code: .invalidJWK)
        }
        
        let header = JWT<DPoPClaimSet>.Header(algorithm: .rs256, type: "dpop+jwt", jwk: jwk)
        let tokenHash = try self.authTokenHash(transactionToken: notificationToken);
        
        let claims = DPoPClaimSet(
            httpURI: url.absoluteString,
            httpMethod: "GET",
            accessTokenHash: tokenHash,
            jti: UUID().uuidString,
            issuedAt: Date())

         let jwt = try JWT<DPoPClaimSet>(claimSet: claims, header: header, key: self.privateKey)
         return jwt.string
    }
    
    private func authTokenHash(transactionToken: String) throws -> String {
        guard let sha256 = A0SHA(algorithm: "sha256") else {
            throw GuardianError(code: .failedCreationDPoPProof)
        }
        
        return sha256.hash(Data(transactionToken.utf8)).base64URLEncodedString()
    }
}
