// EnrollRequest.swift
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

/**
 A request to create a Guardian `Enrollment`
 
 - seealso: Guardian.enroll
 - seealso: Guardian.Enrollment
 */
public class EnrollRequest: Operation {
    public typealias E = EnrolledDevice
    public typealias T = Device

    private let api: API
    private let enrollmentTicket: String?
    private let enrollmentUri: String?
    private let notificationToken: String
    private let verificationKey: VerificationKey
    private let signingKey: SigningKey
    private var request: Request<Device, Enrollment>

    init(api: API, enrollmentTicket: String? = nil, enrollmentUri: String? = nil, notificationToken: String, verificationKey: VerificationKey, signingKey: SigningKey) {
        self.api = api
        self.enrollmentTicket = enrollmentTicket
        self.enrollmentUri = enrollmentUri
        self.notificationToken = notificationToken
        self.verificationKey = verificationKey
        self.signingKey = signingKey
        let ticket: String
        if let enrollmentTicket = enrollmentTicket {
            ticket = enrollmentTicket
        } else if let enrollmentUri = enrollmentUri, let parameters = parameters(fromUri: enrollmentUri), let enrollmentTxId = parameters["enrollment_tx_id"] {
            ticket = enrollmentTxId
        } else {
            let url = self.api.baseUrl.appendingPathComponent("api/enroll")
            self.request = Request(method: .post, url: url, error: GuardianError(code: .invalidErollmentUri))
            return
        }

        self.request = api.enroll(withTicket: ticket, identifier: EnrolledDevice.vendorIdentifier, name: EnrolledDevice.deviceName, notificationToken: notificationToken, verificationKey: self.verificationKey)
    }

    public func on(request: OnRequestEvent? = nil, response: OnResponseEvent? = nil) -> Self {
        self.request = self.request.on(request: request, response: response)
        return self
    }

    public func withURLSession(_ session: URLSession) -> Self {
        self.request = self.request.withURLSession(session)
        return self
    }

    public func mapError(transform: @escaping (HTTPURLResponse, Data?) -> Swift.Error?) -> Self {
        self.request = self.request.mapError(transform: transform)
        return self
    }

    public var description: String {
        return self.request.description
    }

    public var debugDescription: String {
        return self.request.debugDescription
    }

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is
     received
     */
    public func start(callback: @escaping (Result<EnrolledDevice>) -> ()) {
        self.request.start { result in
                switch result {
                case .failure(let cause):
                    callback(.failure(cause: cause))
                case .success(let payload):
                    let enrollment = EnrolledDevice(id: payload.identifier, userId: payload.userId, deviceToken: payload.token, notificationToken: self.notificationToken, signingKey: self.signingKey, totp: payload.totp)
                    callback(.success(payload: enrollment))
                }
        }
    }
}

func parameters(fromUri uri: String) -> [String: String]? {
    guard let components = URLComponents(string: uri), let otp = components.host?.lowercased()
        , components.scheme == "otpauth" && otp == "totp" else {
            return nil
    }
    guard let parameters = components.queryItems?.asDictionary() else {
        return nil
    }
    return parameters
}

private extension Collection where Iterator.Element == URLQueryItem {

    func asDictionary() -> [String: String] {
        return self.reduce([:], { (dict, item) in
            var values = dict
            if let value = item.value {
                values[item.name] = value
            }
            return values
        })
    }
}
