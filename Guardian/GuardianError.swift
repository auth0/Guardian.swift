// GuardianError.swift
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

private let invalidPayloadMessage = "a0.guardian.internal.invalid_payload"
private let invalidResponseMessage = "a0.guardian.internal.invalid_response"
private let failedRequestMessage = "a0.guardian.internal.unknown_server_error"
private let invalidEnrollmentUriMessage = "a0.guardian.internal.invalid_enrollment_uri"
private let invalidBase32SecretMessage = "a0.guardian.internal.invalid_base32_secret"
private let invalidOTPAlgorithmMessage = "a0.guardian.internal.invalid_otp_algorithm"

/**
 An `ErrorType` that encapsulates server and other possible internal errors
 */
public class GuardianError: Error, CustomStringConvertible, Equatable {

    let info: [String: Any]?
    let statusCode: Int
    
    init(info: [String: AnyObject], statusCode: Int) {
        self.info = info
        self.statusCode = statusCode
    }
    
    init(string: String, statusCode: Int = 0) {
        self.info = [
            "errorCode": string
        ]
        self.statusCode = statusCode
    }

    /**
     The code of the error serves as an identifier for the cause of failure.

     You may want to take certain actions based on this value, like displaying
     different error messages to the user.
     */
    public var errorCode: String {
        guard let errorCode = self.info?["errorCode"] as? String else {
            return failedRequestMessage
        }
        return errorCode;
    }
    
    public var description: String {
        return "GuardianError(errorCode=\(errorCode), info=\(info ?? [:]))"
    }
}

public func ==(lhs: GuardianError, rhs: GuardianError) -> Bool {
    return lhs.errorCode == rhs.errorCode && lhs.statusCode == rhs.statusCode
}

internal extension GuardianError {
    static var failedRequest: GuardianError {
        return GuardianError(string: failedRequestMessage)
    }

    static var invalidBase32Secret: GuardianError {
        return GuardianError(string: invalidBase32SecretMessage)
    }

    static var invalidOTPAlgorithm: GuardianError {
        return GuardianError(string: invalidOTPAlgorithmMessage)
    }

    static var invalidPayload: GuardianError {
        return GuardianError(string: invalidPayloadMessage)
    }

    static var invalidResponse: GuardianError {
        return GuardianError(string: invalidResponseMessage)
    }

    static func invalidResponse(withStatus status: Int) -> GuardianError {
        return GuardianError(string: invalidResponseMessage, statusCode: status)
    }

    static var invalidEnrollmentUri: GuardianError {
        return GuardianError(string: invalidEnrollmentUriMessage)
    }
}
