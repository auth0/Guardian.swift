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
        guard let enrollmentData = EnrollmentData(uriString: enrollmentUri) else {
            callback(.Failure(cause: GuardianError(error: .InvalidEnrollmentUriError)))
            return
        }
        api.enrollment(forTransactionId: enrollmentData.enrollmentTxId)
            .start { result in
                switch result {
                case .Failure(let cause):
                    callback(.Failure(cause: cause))
                case .Success(let payload):
                    guard let payload = payload, let deviceToken = payload["device_account_token"] else {
                        callback(.Failure(cause: GuardianError(error: .InvalidResponseError)))
                        return
                    }
                    let enrollment = Enrollment(baseURL: enrollmentData.baseURL, id: enrollmentData.id, deviceToken: deviceToken, apnsToken: self.notificationToken, issuer: enrollmentData.issuer, user: enrollmentData.user, base32Secret: enrollmentData.base32Secret, algorithm: enrollmentData.algorithm, digits: enrollmentData.digits, period: enrollmentData.period)
                    self.api.device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
                        .create(withDeviceIdentifier: enrollment.deviceIdentifier, name: enrollment.deviceName, notificationToken: enrollment.apnsToken)
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
