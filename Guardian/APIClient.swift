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
    let session: URLSession
    
    init(baseUrl: URL, session: URLSession) {
        self.baseUrl = baseUrl
        self.session = session
    }

    func enroll(withTicket enrollmentTicket: String, identifier: String, name: String, notificationToken: String, publicKey: RSAPublicKey) -> DictionaryRequest {
        return DictionaryRequest {
            let url = self.baseUrl.appendingPathComponent("api/enroll")

            guard let jwk = publicKey.jwk else {
                throw GuardianError.invalidPublicKey
            }

            let payload: [String: Any] = [
                "identifier": identifier,
                "name": name,
                "push_credentials": [
                    "service": "APNS",
                    "token": notificationToken
                ],
                "public_key": jwk
            ]
            return Request(session: self.session, method: "POST", url: url, payload: payload, headers: ["Authorization": "Ticket id=\"\(enrollmentTicket)\""])
        }
    }

    func resolve(transaction transactionToken: String, withChallengeResponse challengeResponse: String) -> Request<Void> {
        let payload = [
            "challenge_response": challengeResponse
        ]
        let url = self.baseUrl.appendingPathComponent("api/resolve-transaction")
        return Request(session: self.session, method: "POST", url: url, payload: payload, headers: ["Authorization": "Bearer \(transactionToken)"])
    }

    func device(forEnrollmentId id: String, token: String) -> DeviceAPI {
        return DeviceAPIClient(baseUrl: baseUrl, session: session, id: id, token: token)
    }
}

public struct DictionaryRequest: Requestable {

    typealias T = [String: Any]
    typealias RequestBuilder = () throws -> Request<[String: Any]>

    private let buildRequest: RequestBuilder

    init(builder: @escaping RequestBuilder) {
        self.buildRequest = builder
    }

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is
     received
     */
    public func start(callback: @escaping (Result<[String: Any]>) -> ()) {
        do {
            let request = try buildRequest()
            request.start(callback: callback)
        } catch(let error) {
            callback(.failure(cause: error))
        }
    }
}
