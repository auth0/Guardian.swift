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

public struct EnrollRequest: Requestable {
    
    private let api: API
    private let enrollmentUri: String
    private let notificationToken: String

    typealias T = Enrollment

    init(api: API, enrollmentUri: String, notificationToken: String) {
        self.api = api
        self.enrollmentUri = enrollmentUri
        self.notificationToken = notificationToken
    }
    
    public func start(callback: (Result<Enrollment>) -> ()) {
        guard
            let parameters = parameters(fromUri: enrollmentUri),
            let enrollmentTxId = parameters["enrollment_tx_id"]
            else { return callback(.Failure(cause: GuardianError.invalidEnrollmentUri)) }
        let enroll = { (enrollment: Enrollment) in
            self.api.device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
                .create(withDeviceIdentifier: enrollment.deviceIdentifier, name: enrollment.deviceName, notificationToken: enrollment.notificationToken)
                .start { result in
                    switch result {
                    case .Failure(let cause):
                        callback(.Failure(cause: cause))
                    case .Success(_):
                        callback(.Success(payload: enrollment))
                    }
            }
        }
        self.api.enrollment(forTransactionId: enrollmentTxId)
            .start { result in
                switch result {
                case .Failure(let cause):
                    callback(.Failure(cause: cause))
                case .Success(let payload):
                    guard
                        let payload = payload,
                        let deviceToken = payload["device_account_token"] else {
                        return callback(.Failure(cause: GuardianError.invalidResponse))
                    }
                    guard let enrollment = enrollment(usingParameters: parameters, withNotificationToken: self.notificationToken, deviceToken: deviceToken) else {
                        return callback(.Failure(cause: GuardianError.invalidEnrollmentUri))
                    }
                    enroll(enrollment)
                }
        }
    }
}
func parameters(fromUri uri: String) -> [String: String]? {
    guard let components = NSURLComponents(string: uri), let otp = components.host?.lowercaseString
        where components.scheme == "otpauth" && otp == "totp" else {
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

    let digits = Int(parameters["digits"]) ?? 6
    let period = Int(parameters["period"]) ?? 30
    let algorithm = parameters["algorithm"] ?? "sha1"
    return Enrollment(id: id, deviceToken: deviceToken, notificationToken: notificationToken, base32Secret: secret, algorithm: algorithm, digits: digits, period: period)
}

private extension Int {

    init?(_ value: String?) {
        guard let value = value else { return nil }
        self.init(value)
    }
}

private extension Array where Element: NSURLQueryItem {

    func asDictionary() -> [String: String] {
        return self.reduce([:], combine: { (dict, item) in
            var values = dict
            if let value = item.value {
                values[item.name] = value
            }
            return values
        })
    }
}
