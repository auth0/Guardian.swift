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
public class EnrollRequest: Requestable {

    typealias T = Enrollment

    private let api: API
    private let enrollmentTicket: String?
    private let enrollmentUri: String?
    private let notificationToken: String
    private let keyPair: RSAKeyPair
    private var request: Request<[String: Any]>

    init(api: API, enrollmentTicket: String? = nil, enrollmentUri: String? = nil, notificationToken: String, keyPair: RSAKeyPair) {
        self.api = api
        self.enrollmentTicket = enrollmentTicket
        self.enrollmentUri = enrollmentUri
        self.notificationToken = notificationToken
        self.keyPair = keyPair
        let ticket: String
        if let enrollmentTicket = enrollmentTicket {
            ticket = enrollmentTicket
        } else if let enrollmentUri = enrollmentUri, let parameters = parameters(fromUri: enrollmentUri), let enrollmentTxId = parameters["enrollment_tx_id"] {
            ticket = enrollmentTxId
        } else {
            self.request = FailedRequest(error: GuardianError.invalidEnrollmentUri)
            return
        }

        self.request = api.enroll(withTicket: ticket, identifier: Enrollment.defaultDeviceIdentifier, name: Enrollment.defaultDeviceName, notificationToken: notificationToken, publicKey: keyPair.publicKey)
    }

    /// Registers hooks to be called on specific events:
    ///  * on request being sent
    ///  * on response recieved (successful or not)
    ///  * on network error
    ///
    /// - Parameters:
    ///   - request: closure called with request information
    ///   - response: closure called with response and data
    ///   - error: closure called with network error
    /// - Returns: itself for chaining
    public func on(request: RequestHook? = nil, response: ResponseHook? = nil, error: ErrorHook? = nil) -> EnrollRequest {
        let _ = self.request.on(request: request, response: response, error: error)
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
    public func start(callback: @escaping (Result<Enrollment>) -> ()) {
        self.request.start { result in
                switch result {
                case .failure(let cause):
                    callback(.failure(cause: cause))
                case .success(let payload):
                    guard
                        let id = payload["id"] as? String,
                        let token = payload["token"] as? String,
                        let userId = payload["user_id"] as? String,
                        let _ = payload["issuer"] as? String,
                        let _ = payload["url"] as? String else {
                            return callback(.failure(cause: GuardianError.invalidResponse))
                    }

                    let totpData = payload["totp"] as? [String: Any]
                    let totpSecret = totpData?["secret"] as? String
                    let totpAlgorithm = totpData?["algorithm"] as? String
                    let totpPeriod = totpData?["period"] as? Int
                    let totpDigits = totpData?["digits"] as? Int

                    let enrollment = Enrollment(id: id, userId: userId, deviceToken: token, notificationToken: self.notificationToken, signingKey: self.keyPair.privateKey, base32Secret: totpSecret, algorithm: totpAlgorithm, digits: totpDigits, period: totpPeriod)
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
