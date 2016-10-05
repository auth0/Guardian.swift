// Authentication.swift
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

public protocol Authentication {
    func allow(notification notification: Notification) -> GuardianRequest
    func reject(notification notification: Notification, withReason reason: String?) -> GuardianRequest
}

public extension Authentication {
    public func reject(notification notification: Notification, withReason reason: String? = nil) -> GuardianRequest {
        return self.reject(notification: notification, withReason: reason)
    }
}

struct TOTPAuthentication: Authentication {

    let api: API
    let enrollment: Enrollment

    func allow(notification notification: Notification) -> GuardianRequest {
        return GuardianRequest {
            let code = try totp(from: self.enrollment)
                .generate(digits: self.enrollment.digits, counter: Int(NSDate().timeIntervalSince1970))
            return self.api
                .allow(transaction: notification.transactionToken, withCode: code)
        }
    }

    func reject(notification notification: Notification, withReason reason: String? = nil) -> GuardianRequest {
        return GuardianRequest {
            let code = try totp(from: self.enrollment)
                .generate(digits: self.enrollment.digits, counter: Int(NSDate().timeIntervalSince1970))
            return self.api
                .reject(transaction: notification.transactionToken, withCode: code, reason: reason)
        }
    }
}

func totp(from enrollment: Enrollment) throws -> TOTP {
    guard let key = Base32.decode(enrollment.base32Secret) else {
        throw GuardianError.invalidBase32Secret
    }
    guard let totp = TOTP(withKey: key, period: enrollment.period, algorithm: enrollment.algorithm) else {
        throw GuardianError.invalidOTPAlgorithm
    }
    return totp
}

public struct GuardianRequest: Requestable {

    typealias T = Void
    typealias RequestBuilder = () throws -> Request<Void>

    private let buildRequest: RequestBuilder

    init(builder: RequestBuilder) {
        self.buildRequest = builder
    }

    public func start(callback: (Result<Void>) -> ()) {
        do {
            let request = try buildRequest()
            request.start(callback)
        } catch(let error) {
            callback(.Failure(cause: error))
        }
    }
}
