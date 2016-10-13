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
public struct EnrollRequest: Requestable {

    typealias T = Enrollment

    private let api: API
    private let enrollmentUri: String
    private let notificationToken: String

    init(api: API, enrollmentUri: String, notificationToken: String) {
        self.api = api
        self.enrollmentUri = enrollmentUri
        self.notificationToken = notificationToken
    }

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is
     received
     */
    public func start(callback: @escaping (Result<Enrollment>) -> ()) {
        guard
            let parameters = parameters(fromUri: enrollmentUri),
            let enrollmentTxId = parameters["enrollment_tx_id"]
            else { return callback(.failure(cause: GuardianError.invalidEnrollmentUri)) }
        let enroll = { (enrollment: Enrollment) in
            self.api.device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
                .create(withDeviceIdentifier: enrollment.deviceIdentifier, name: enrollment.deviceName, notificationToken: enrollment.notificationToken)
                .start { result in
                    switch result {
                    case .failure(let cause):
                        callback(.failure(cause: cause))
                    case .success:
                        callback(.success(payload: enrollment))
                    }
            }
        }
        self.api.enrollment(forTransactionId: enrollmentTxId)
            .start { result in
                switch result {
                case .failure(let cause):
                    callback(.failure(cause: cause))
                case .success(let payload):
                    guard
                        let payload = payload,
                        let deviceToken = payload["device_account_token"] else {
                        return callback(.failure(cause: GuardianError.invalidResponse))
                    }
                    guard let enrollment = enrollment(usingParameters: parameters, withNotificationToken: self.notificationToken, deviceToken: deviceToken) else {
                        return callback(.failure(cause: GuardianError.invalidEnrollmentUri))
                    }
                    enroll(enrollment)
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

func enrollment(usingParameters parameters: [String: String], withNotificationToken notificationToken: String, deviceToken: String) -> Enrollment? {
    guard
        let id = parameters["id"],
        let secret = parameters["secret"]
        else { return nil }

    let digits = Int(parameters["digits"])
    let period = Int(parameters["period"])
    let algorithm = parameters["algorithm"]
    return Enrollment(id: id, deviceToken: deviceToken, notificationToken: notificationToken, base32Secret: secret, algorithm: algorithm, digits: digits, period: period)
}

private extension Int {

    init?(_ value: String?) {
        guard let value = value else { return nil }
        self.init(value)
    }
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
