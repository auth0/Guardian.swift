// Guardian.swift
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

public struct Guardian {

    private let api: API
    private let codeGenerator: CodeGenerator
    
    public init(baseUrl: NSURL, session: NSURLSession = NSURLSession.sharedSession(), codeGenerator: CodeGenerator = TOTPCodeGenerator()) {
        self.api = APIClient(baseUrl: baseUrl, session: session)
        self.codeGenerator = codeGenerator
    }

    public func enroll(withUri enrollmentUri: String, notificationToken: String) -> EnrollRequest {
        return EnrollRequest(api: api, enrollmentUri: enrollmentUri, notificationToken: notificationToken)
    }

    public func delete(enrollment enrollment: Enrollment) -> Request<Void> {
        return api
            .device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
            .delete()
    }

    public func allow(notification notification: Notification, enrollment: Enrollment) -> GuardianRequest<Void> {
        return GuardianRequest {
            let code = try self.codeGenerator.generate(forEnrollment: enrollment)
            return self.api
                .allow(transaction: notification.transactionToken, withCode: code)
        }
    }

    public func reject(notification notification: Notification, withReason reason: String? = nil, enrollment: Enrollment) -> GuardianRequest<Void> {
        return GuardianRequest {
            let code = try self.codeGenerator.generate(forEnrollment: enrollment)
            return self.api
                .reject(transaction: notification.transactionToken, withCode: code, reason: reason)
        }
    }
}

public enum CodeGeneratorError: ErrorType {
    case InvalidSecret
    case InvalidAlgorithm(String)
}

public protocol CodeGenerator {
    func generate(forEnrollment enrollment: Enrollment) throws -> String
}

struct TOTPCodeGenerator: CodeGenerator {
    func generate(forEnrollment enrollment: Enrollment) throws -> String {
        guard let key = Base32.decode(enrollment.base32Secret) else {
            throw CodeGeneratorError.InvalidSecret
        }
        guard let algorithm = Algorithm(rawValue: enrollment.algorithm.lowercaseString) else {
            throw CodeGeneratorError.InvalidAlgorithm(enrollment.algorithm)
        }
        let generator = TOTP(withKey: key, period: enrollment.period, algorithm: algorithm)
        return generator.generate(digits: enrollment.digits, counter: Int(NSDate().timeIntervalSince1970))
    }
}

public struct GuardianRequest<T>: Requestable {

    typealias RequestBuilder = () throws -> Request<T>

    private let buildRequest: RequestBuilder

    init(builder: RequestBuilder) {
        self.buildRequest = builder
    }

    public func start(callback: (Result<T>) -> ()) {
        do {
            let request = try buildRequest()
            request.start(callback)
        } catch(let error) {
            callback(.Failure(cause: error))
        }
    }
}
