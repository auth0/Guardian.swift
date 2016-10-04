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

public class GuardianError: ErrorType, CustomStringConvertible {
    
    enum InternalError: String {
        case InvalidPayloadError        = "a0.guardian.internal.invalid_payload"
        case InvalidResponseError       = "a0.guardian.internal.invalid_response"
        case UnknownServerError         = "a0.guardian.internal.unknown_server_error"
        case InvalidEnrollmentUriError  = "a0.guardian.internal.invalid_enrollment_uri"
    }
    
    let info: [String: AnyObject]?
    let statusCode: Int
    
    init(info: [String: AnyObject], statusCode: Int) {
        self.info = info
        self.statusCode = statusCode
    }
    
    init(error: InternalError, statusCode: Int = 0) {
        self.info = [
            "errorCode": error.rawValue
        ]
        self.statusCode = statusCode
    }
    
    var errorCode: String {
        guard let errorCode = self.info?["errorCode"] as? String else {
            return InternalError.UnknownServerError.rawValue
        }
        return errorCode;
    }
    
    public var description: String {
        return "GuardianError(errorCode=\(errorCode), info=\(info ?? [:]))"
    }
}
