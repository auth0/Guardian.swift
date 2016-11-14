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

/**
 An `Authentication` lets you allow or reject a `Notification`
 
 ```
 let enrollment: Enrollment = // the object you obtained when enrolling
 let authenticator = Guardian
    .authentication(forDomain: "tenant.guardian.auth0.com", andEnrollment: enrollment)
 ```
 */
public protocol Authentication {

    /**
     Allows/verifies the authentication request

     ```
     let enrollment: Enrollment = // the object you obtained when enrolling
     let notification: Notification = // the notification received
     Guardian
        .authentication(forDomain: "tenant.guardian.auth0.com", andEnrollment: enrollment)
        .allow(notification: notification)
        .start { result in
            switch result {
            case .Success(_):
                // auth request allowed successfuly
            case .Failure(let cause):
                // failed to allow auth request
            }
     }
     ```

     - parameter notification: the notification that contains the authentication
                               request that should be allowed.
     
     - returns: a request to execute
     */
    func allow(notification: Notification) -> VoidRequest

    /**
     Reject/denies the authentication request
     
     ```
     let enrollment: Enrollment = // the object you obtained when enrolling
     let notification: Notification = // the notification received
     Guardian
        .authentication(forDomain: "tenant.guardian.auth0.com", andEnrollment: enrollment)
        .reject(notification: notification, withReason: "mistake")
        .start { result in
            switch result {
            case .Success(_):
                // auth request rejected successfuly
            case .Failure(let cause):
                // failed to reject auth request
            }
     }
     ```

     - parameter notification: the notification that contains the authentication
                               request that should be allowed.
     - parameter withReason:   an optional string that identifies the reason why
                               this authentication request is being rejected.

     - returns: a request to execute
     */
    func reject(notification: Notification, withReason reason: String?) -> VoidRequest
}

public extension Authentication {
    public func reject(notification: Notification, withReason reason: String? = nil) -> VoidRequest {
        return self.reject(notification: notification, withReason: reason)
    }
}

struct TOTPAuthentication: Authentication {

    let api: API
    let enrollment: Enrollment

    func allow(notification: Notification) -> VoidRequest {
        return VoidRequest {
            let code = try totp(from: self.enrollment)
                .generate(digits: self.enrollment.digits, counter: Int(Date().timeIntervalSince1970))
            return self.api
                .allow(transaction: notification.transactionToken, withCode: code)
        }
    }

    func reject(notification: Notification, withReason reason: String? = nil) -> VoidRequest {
        return VoidRequest {
            let code = try totp(from: self.enrollment)
                .generate(digits: self.enrollment.digits, counter: Int(Date().timeIntervalSince1970))
            return self.api
                .reject(transaction: notification.transactionToken, withCode: code, reason: reason)
        }
    }
}

func totp(from enrollment: Enrollment) throws -> TOTP {
    guard let base32Secret = enrollment.base32Secret, let key = Base32.decode(string: base32Secret) else {
        throw GuardianError.invalidBase32Secret
    }
    guard let totp = TOTP(withKey: key, period: enrollment.period, algorithm: enrollment.algorithm) else {
        throw GuardianError.invalidOTPAlgorithm
    }
    return totp
}

public struct VoidRequest: Requestable {

    typealias T = Void
    typealias RequestBuilder = () throws -> Request<Void>

    private let buildRequest: RequestBuilder

    init(builder: @escaping RequestBuilder) {
        self.buildRequest = builder
    }

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is
     received
     */
    public func start(callback: @escaping (Result<()>) -> ()) {
        do {
            let request = try buildRequest()
            request.start(callback: callback)
        } catch(let error) {
            callback(.failure(cause: error))
        }
    }
}
