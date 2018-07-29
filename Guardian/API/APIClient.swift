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

struct PushCredentials: Codable {
    let service = "APNS"
    let token: String
}

public struct RSAPublicJWK: Codable {
    public let keyType = "RSA"
    public let usage = "sig"
    public let algorithm = "RS256"
    public let modulus: String
    public let exponent: String

    enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case usage = "use"
        case algorithm = "alg"
        case modulus = "n"
        case exponent = "e"
    }
}

public struct Device: Encodable {
    let identifier: String
    let name: String
    let pushCredentials: PushCredentials
    let publicKey: RSAPublicJWK

    enum CodingKeys: String, CodingKey {
        case identifier
        case name
        case pushCredentials = "push_credentials"
        case publicKey = "public_key"
    }
}

public struct Enrollment: Decodable{
    let identifier: String
    let token: String
    let userId: String
    let issuer: String
    let totp: OTPParameters?

    enum CodingKeys: String, CodingKey {
        case identifier = "id"
        case token
        case userId = "user_id"
        case issuer
        case totp
    }
}

public struct Transaction: Codable {
    let challengeResponse: String

    enum CodingKeys: String, CodingKey {
        case challengeResponse = "challenge_response"
    }
}

let errorBuilder = { (response: HTTPURLResponse, data: Data?) -> Error? in
    guard let data = data, let json = try? JSONSerialization.jsonObject(with: data, options: []), let info = json as? [String: Any] else { return nil }
    return GuardianError(info: info, statusCode: response.statusCode)
}

public struct GuardianRequest<T: Encodable, E: Decodable>: Operation {
    let request: NetworkOperation<T, E>

    static func new(method: HTTPMethod, url: URL, headers: [String: String] = [:], body: T? = nil) -> GuardianRequest<T, E>{
        do {
            let request: NetworkOperation<T, E> = try NetworkOperation(method: method, url: url, headers: headers, body: body)
            return GuardianRequest(request: request)
        } catch let error {
            return GuardianRequest(method: method, url: url, error: error)
        }
    }

    init(request: NetworkOperation<T, E>) {
        self.request = request.mapError(transform: errorBuilder)
    }

    init(method: HTTPMethod, url: URL, error: Error) {
        let request: NetworkOperation<T, E> = NetworkOperation(method: method, url: url, error: error)
        self.init(request: request)
    }

    public func start(callback: @escaping (Result<E>) -> ()) {
        self.request.start(callback: callback)
    }

    public func on(request: OnRequestEvent? = nil, response: OnResponseEvent? = nil) -> GuardianRequest<T, E> {
        let request = self.request.on(request: request, response: response)
        return GuardianRequest(request: request)
    }

    public func mapError(transform: @escaping (HTTPURLResponse, Data?) -> Error?) -> GuardianRequest<T, E> {
        let request = self.request.mapError { (response, data) -> Error? in
            return transform(response, data) ?? errorBuilder(response, data)
        }
        return GuardianRequest(request: request)
    }

    public func withURLSession(_ session: URLSession) -> GuardianRequest<T, E> {
        let request = self.request.withURLSession(session)
        return GuardianRequest(request: request)
    }

    public var description: String { return self.request.description }
    public var debugDescription: String { return self.request.debugDescription }
}


struct APIClient: API {

    let baseUrl: URL

    init(baseUrl: URL) {
        self.baseUrl = baseUrl
    }

    func enroll(withTicket enrollmentTicket: String, identifier: String, name: String, notificationToken: String, verificationKey: VerificationKey) -> GuardianRequest<Device, Enrollment> {
        let url = self.baseUrl.appendingPathComponent("api/enroll")
        do {
            let headers = ["Authorization": "Ticket id=\"\(enrollmentTicket)\""]
            guard let jwk = verificationKey.jwk else {
                throw GuardianError.invalidPublicKey
            }

            let device = Device(identifier: identifier, name: name, pushCredentials: PushCredentials(token: notificationToken), publicKey: jwk)
            return GuardianRequest.new(method: .post, url: url, headers: headers, body: device)
        }
        catch let error {
            return GuardianRequest(method: .post, url: url, error: error)
        }
    }

    func resolve(transaction transactionToken: String, withChallengeResponse challengeResponse: String) -> GuardianRequest<Transaction, NoContent> {
        let transaction = Transaction(challengeResponse: challengeResponse)
        let url = self.baseUrl.appendingPathComponent("api/resolve-transaction")
        return GuardianRequest.new(method: .post, url: url, headers: ["Authorization": "Bearer \(transactionToken)"], body: transaction)
    }

    func device(forEnrollmentId id: String, token: String) -> DeviceAPI {
        return DeviceAPIClient(baseUrl: baseUrl, id: id, token: token)
    }
}
