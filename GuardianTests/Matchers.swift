// Matchers.swift
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
import OHHTTPStubs
import Nimble

@testable import Guardian

func hasAllOf(parameters: [String: String]) -> OHHTTPStubsTestBlock {
    return { request in
        guard let payload = request.a0_payload else { return false }
        return parameters.count == payload.count && parameters.reduce(true, combine: { (initial, entry) -> Bool in
            return initial && payload[entry.0] as? String == entry.1
        })
    }
}

func hasAtLeast(parameters: [String: String]) -> OHHTTPStubsTestBlock {
    return { request in
        guard let payload = request.a0_payload else { return false }
        let entries = parameters.filter { (key, _) in payload.contains { (name, _) in  key == name } }
        return entries.count == parameters.count && entries.reduce(true, combine: { (initial, entry) -> Bool in
            return initial && payload[entry.0] as? String == entry.1
        })
    }
}

func hasObjectAttribute(name: String, value: [String: String]) -> OHHTTPStubsTestBlock {
    return { request in
        guard let payload = request.a0_payload, actualValue = payload[name] as? [String: AnyObject] else { return false }
        return value.count == actualValue.count && value.reduce(true, combine: { (initial, entry) -> Bool in
            guard let value = actualValue[entry.0] as? String else { return false }
            return initial && value == entry.1
        })
    }
}

func hasNoneOf(names: [String]) -> OHHTTPStubsTestBlock {
    return { request in
        guard let payload = request.a0_payload else { return false }
        return payload.filter { names.contains($0.0) }.isEmpty
    }
}

func hasNoneOf(parameters: [String: String]) -> OHHTTPStubsTestBlock {
    return !hasAtLeast(parameters)
}

func hasQueryParameters(parameters: [String: String]) -> OHHTTPStubsTestBlock {
    return { request in
        guard
            let url = request.URL,
            let components = NSURLComponents(URL: url, resolvingAgainstBaseURL: true),
            let items = components.queryItems
            else { return false }
        return items.count == parameters.count && items.reduce(true, combine: { (initial, item) -> Bool in
            return initial && parameters[item.name] == item.value
        })
    }
}

func hasBearerToken(token: String) -> OHHTTPStubsTestBlock {
    return { request in
        return request.valueForHTTPHeaderField("Authorization") == "Bearer \(token)"
    }
}

func isPathStartingWith(path: String) -> OHHTTPStubsTestBlock {
    return { req in
        guard let path = req.URL?.path, let range = path.rangeOfString(path) else {
            return false
        }
        return range.startIndex == path.startIndex
    }
}

func isEnrollmentInfo(domain domain: String) -> OHHTTPStubsTestBlock {
    return isScheme("https") && isHost(domain) && isMethodPOST() && isPath("/api/enrollment-info")
}

func isVerifyOTP(domain domain: String) -> OHHTTPStubsTestBlock {
    return isScheme("https") && isHost(domain) && isMethodPOST() && isPath("/api/verify-otp")
}

func isRejectLogin(domain domain: String) -> OHHTTPStubsTestBlock {
    return isScheme("https") && isHost(domain) && isMethodPOST() && isPath("/api/reject-login")
}

func isEnrollment(domain domain: String, enrollmentId: String? = nil) -> OHHTTPStubsTestBlock {
    if let enrollmentId = enrollmentId {
        return isHost(domain) && isPath("/api/device-accounts/\(enrollmentId)")
    }
    return isHost(domain) && isPathStartingWith("/api/device-accounts/")
}

func isDeleteEnrollment(domain domain: String, enrollmentId: String? = nil) -> OHHTTPStubsTestBlock {
    return isMethodDELETE() && isEnrollment(domain: domain, enrollmentId: enrollmentId)
}

func isUpdateEnrollment(domain domain: String, enrollmentId: String? = nil) -> OHHTTPStubsTestBlock {
    return isMethodPATCH() && isEnrollment(domain: domain, enrollmentId: enrollmentId)
}

func haveDeviceAccountToken(deviceAccountToken: String?) -> MatcherFunc<Result<[String:String]>> {
    return MatcherFunc { expression, failureMessage in
        var message = "be a successful enrollment info result with"
        if let deviceAccountToken = deviceAccountToken {
            message = message.stringByAppendingString(" <device_account_token: \(deviceAccountToken)>")
        }
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .Success(let result) = actual {
            if let token = result?["device_account_token"] {
                return deviceAccountToken == token
            }
        }
        return false
    }
}

func haveEnrollment(withId enrollmentId: String?, deviceIdentifier: String?, deviceName: String?, notificationService: String?, notificationToken: String?) -> MatcherFunc<Result<[String:AnyObject]>> {
    return MatcherFunc { expression, failureMessage in
        var message = "be a successful enrollment info result with"
        if let enrollmentId = enrollmentId {
            message = message.stringByAppendingString(" <id: \(enrollmentId)>")
        }
        if let deviceIdentifier = deviceIdentifier {
            message = message.stringByAppendingString(" <identifier: \(deviceIdentifier)>")
        }
        if let deviceName = deviceName {
            message = message.stringByAppendingString(" <name: \(deviceName)>")
        }
        if let notificationService = notificationService {
            message = message.stringByAppendingString(" <push_credentials.service: \(notificationService)>")
        }
        if let notificationToken = notificationToken {
            message = message.stringByAppendingString(" <push_credentials.token: \(notificationToken)>")
        }
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .Success(let result) = actual {
            if let result = result {
                if let enrollmentId = enrollmentId {
                    guard let id = result["id"] as? String where id == enrollmentId else {
                        return false
                    }
                }
                if let deviceIdentifier = deviceIdentifier {
                    guard let identifier = result["identifier"] as? String where identifier == deviceIdentifier else {
                        return false
                    }
                }
                if let deviceName = deviceName {
                    guard let name = result["name"] as? String where name == deviceName else {
                        return false
                    }
                }
                if notificationService != nil || notificationToken != nil {
                    guard let pushCredentials = result["push_credentials"] as? [String:String] else {
                        return false
                    }
                    if let notificationService = notificationService {
                        guard let service = pushCredentials["service"] where service == notificationService else {
                            return false
                        }
                    }
                    if let notificationToken = notificationToken {
                        guard let token = pushCredentials["token"] where token == notificationToken else {
                            return false
                        }
                    }
                }
                return true
            }
        }
        return false
    }
}

func haveError<T>(withErrorCode errorCode: String? = nil) -> MatcherFunc<Result<T>> {
    return MatcherFunc { expression, failureMessage in
        var message = "be an error response with"
        if let errorCode = errorCode {
            message = message.stringByAppendingString(" <errorCode: \(errorCode)>")
        }
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .Failure(let cause) = actual {
            if let error = cause as? GuardianError {
                return errorCode == error.errorCode
            }
        }
        return false
    }
}

func beSuccess<T>() -> MatcherFunc<Result<T>> {
    return MatcherFunc { expression, failureMessage in
        let message = "be an empty success response"
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .Success(_) = actual {
            return true
        }
        return false
    }
}

extension NSURLRequest {
    var a0_payload: [String: AnyObject]? {
        guard let data = OHHTTPStubs_HTTPBody() else { return nil }
        let object = try? NSJSONSerialization.JSONObjectWithData(data, options: [])
        return object as? [String: AnyObject]
    }
}
