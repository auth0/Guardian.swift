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
    
    init(api: API, enrollmentUri: String, notificationToken: String) {
        self.api = api
        self.enrollmentUri = enrollmentUri
        self.notificationToken = notificationToken
    }
    
    public func start(callback: (Result<Enrollment>) -> ()) {
        guard let (enrollmentTxId, enrollmentData) = enrollmentData(fromURI: enrollmentUri, notificationToken: notificationToken) else {
            return callback(.Failure(cause: GuardianError(error: .InvalidEnrollmentUriError)))
        }
        let api = self.api
        api.enrollment(forTransactionId: enrollmentTxId)
            .start { result in
                switch result {
                case .Failure(let cause):
                    callback(.Failure(cause: cause))
                case .Success(let payload):
                    guard let payload = payload, let deviceToken = payload["device_account_token"] else {
                        return callback(.Failure(cause: GuardianError(error: .InvalidResponseError)))
                    }
                    let enrollment = Enrollment(
                        baseURL: enrollmentData.baseURL,
                        id: enrollmentData.id,
                        deviceToken: deviceToken,
                        notificationToken: enrollmentData.notificationToken,
                        issuer: enrollmentData.issuer,
                        user: enrollmentData.user,
                        base32Secret: enrollmentData.base32Secret,
                        algorithm: enrollmentData.algorithm,
                        digits: enrollmentData.digits,
                        period: enrollmentData.period)
                    api.device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
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
        }
    }
}

func enrollmentData(fromURI uriString: String, notificationToken: String) -> (enrollmentTxId: String, enrollment: Enrollment)? {
    guard let components = NSURLComponents(string: uriString), let otp = components.host?.lowercaseString
        where components.scheme == "otpauth" && otp == "totp" else {
            return nil
    }
    guard let path = components.path where !path.isEmpty, let parameters = components.queryItems?.asDictionary() else {
        return nil
    }
    var label = path.substringFromIndex(path.startIndex.advancedBy(1))
    var issuer: String?
    if label.containsString(":") {
        let labelParts = label.componentsSeparatedByString(":")
        issuer = labelParts[0]
        label = labelParts[1]
    }
    if let issuerParam = parameters["issuer"] {
        guard issuer == nil || issuer == issuerParam else {
            return nil
        }
        issuer = issuerParam
    }
    guard let issuer2 = issuer,
        let id = parameters["id"],
        let secret = parameters["secret"],
        let enrollmentTxId = parameters["enrollment_tx_id"],
        let urlString = parameters["base_url"],
        let url = NSURL(string: urlString) else {
            return nil
    }

    let enrollment = Enrollment(baseURL: url, id: id, deviceToken: "", notificationToken: notificationToken, issuer: issuer2, user: label, base32Secret: secret, algorithm: parameters["algorithm"], digits: Int(parameters["digits"]), period: Int(parameters["period"]))

    return (enrollmentTxId, enrollment)
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
