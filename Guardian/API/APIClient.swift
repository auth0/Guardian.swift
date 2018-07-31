// APIClient.swift
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

import Foundation

struct APIClient: API {

    let baseUrl: URL

    init(baseUrl: URL) {
        self.baseUrl = baseUrl
    }

    func enroll(withTicket enrollmentTicket: String, identifier: String, name: String, notificationToken: String, verificationKey: VerificationKey) -> Request<Device, Enrollment> {
        let url = self.baseUrl.appendingPathComponent("api/enroll")
        do {
            let headers = ["Authorization": "Ticket id=\"\(enrollmentTicket)\""]
            guard let jwk = verificationKey.jwk else {
                throw GuardianError(code: .invalidJWK)
            }

            let device = Device(identifier: identifier, name: name, pushCredentials: PushCredentials(token: notificationToken), publicKey: jwk)
            return Request.new(method: .post, url: url, headers: headers, body: device)
        }
        catch let error {
            return Request(method: .post, url: url, error: error)
        }
    }

    func resolve(transaction transactionToken: String, withChallengeResponse challengeResponse: String) -> Request<Transaction, NoContent> {
        let transaction = Transaction(challengeResponse: challengeResponse)
        let url = self.baseUrl.appendingPathComponent("api/resolve-transaction")
        return Request.new(method: .post, url: url, headers: ["Authorization": "Bearer \(transactionToken)"], body: transaction)
    }

    func device(forEnrollmentId id: String, token: String) -> DeviceAPI {
        return DeviceAPIClient(baseUrl: baseUrl, id: id, token: token)
    }
}
