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

func hasAtLeast(_ parameters: [String: String]) -> OHHTTPStubsTestBlock {
    return { request in
        guard let payload = request.a0_payload else { return false }
        let entries = parameters.filter { (key, _) in payload.contains { (name, _) in  key == name } }
        return entries.count == parameters.count && entries.reduce(true, { (initial, entry) -> Bool in
            return initial && payload[entry.0] as? String == entry.1
        })
    }
}

func hasField(_ field: String, withParameters parameters: [String: String]) -> OHHTTPStubsTestBlock {
    return { request in
        guard
            let payload = request.a0_payload,
            let pushCredentials = payload[field] as? [String: Any]
            else { return false }
        let entries = parameters.filter { (key, _) in pushCredentials.contains { (name, _) in  key == name } }
        return entries.count == parameters.count && entries.reduce(true, { (initial, entry) -> Bool in
            return initial && pushCredentials[entry.0] as? String == entry.1
        })
    }
}

func hasNoneOf(_ names: [String]) -> OHHTTPStubsTestBlock {
    return { request in
        guard let payload = request.a0_payload else { return false }
        return payload.filter { names.contains($0.0) }.isEmpty
    }
}

func hasNoneOf(_ parameters: [String: String]) -> OHHTTPStubsTestBlock {
    return !hasAtLeast(parameters)
}

func hasBearerToken(_ token: String) -> OHHTTPStubsTestBlock {
    return { request in
        return request.value(forHTTPHeaderField: "Authorization") == "Bearer \(token)"
    }
}

func hasTicketAuth(_ ticket: String) -> OHHTTPStubsTestBlock {
    return { request in
        return request.value(forHTTPHeaderField: "Authorization") == "Ticket id=\"\(ticket)\""
    }
}

func isUrl(from baseUrl: URL, containingPathStartingWith path: String) -> OHHTTPStubsTestBlock {
    return { req in
        let partialUrl = baseUrl.appendingPathComponent(path).absoluteString
        guard let url = req.url?.absoluteString
            , let range = url.range(of: partialUrl) else {
            return false
        }
        return range.lowerBound == path.startIndex
    }
}

func isUrl(from baseUrl: URL, endingWithPathComponent pathComponent: String) -> OHHTTPStubsTestBlock {
    return { req in
        return req.url == baseUrl.appendingPathComponent(pathComponent)
    }
}


func isEnrollmentInfo(baseUrl: URL) -> OHHTTPStubsTestBlock {
    return isScheme("https") && isMethodPOST() && isUrl(from: baseUrl, endingWithPathComponent: "api/enrollment-info")
}

func isMobileEnroll(baseUrl: URL) -> OHHTTPStubsTestBlock {
    return isScheme("https") && isMethodPOST() && isUrl(from: baseUrl, endingWithPathComponent: "api/enroll")
}

func isResolveTransaction(baseUrl: URL) -> OHHTTPStubsTestBlock {
    return isScheme("https") && isMethodPOST() && isUrl(from: baseUrl, endingWithPathComponent: "api/resolve-transaction")
}

func isEnrollment(baseUrl: URL, enrollmentId: String? = nil) -> OHHTTPStubsTestBlock {
    if let enrollmentId = enrollmentId {
        return isUrl(from: baseUrl, endingWithPathComponent: "api/device-accounts/\(enrollmentId)")
    }
    return isUrl(from: baseUrl, containingPathStartingWith: "api/device-accounts/")
}

func isDeleteEnrollment(baseUrl: URL, enrollmentId: String? = nil) -> OHHTTPStubsTestBlock {
    return isMethodDELETE() && isEnrollment(baseUrl: baseUrl, enrollmentId: enrollmentId)
}

func isUpdateEnrollment(baseUrl: URL, enrollmentId: String? = nil) -> OHHTTPStubsTestBlock {
    return isMethodPATCH() && isEnrollment(baseUrl: baseUrl, enrollmentId: enrollmentId)
}

func haveDeviceAccountToken(_ deviceAccountToken: String?) -> MatcherFunc<Result<[String: String]>> {
    return MatcherFunc { expression, failureMessage in
        var message = "be a successful enrollment info result with"
        if let deviceAccountToken = deviceAccountToken {
            message = message.appending(" <device_account_token: \(deviceAccountToken)>")
        }
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .success(let result) = actual {
            if let token = result["device_account_token"] {
                return deviceAccountToken == token
            }
        }
        return false
    }
}

func haveEnrollment(withId enrollmentId: String?, deviceIdentifier: String?, deviceName: String?, notificationService: String?, notificationToken: String?) -> MatcherFunc<Result<[String: Any]>> {
    return MatcherFunc { expression, failureMessage in
        var message = "be a successful enrollment info result with"
        if let enrollmentId = enrollmentId {
            message = message.appending(" <id: \(enrollmentId)>")
        }
        if let deviceIdentifier = deviceIdentifier {
            message = message.appending(" <identifier: \(deviceIdentifier)>")
        }
        if let deviceName = deviceName {
            message = message.appending(" <name: \(deviceName)>")
        }
        if let notificationService = notificationService {
            message = message.appending(" <push_credentials.service: \(notificationService)>")
        }
        if let notificationToken = notificationToken {
            message = message.appending(" <push_credentials.token: \(notificationToken)>")
        }
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .success(let result) = actual {
            if let enrollmentId = enrollmentId {
                guard let id = result["id"] as? String , id == enrollmentId else {
                    return false
                }
            }
            if let deviceIdentifier = deviceIdentifier {
                guard let identifier = result["identifier"] as? String , identifier == deviceIdentifier else {
                    return false
                }
            }
            if let deviceName = deviceName {
                guard let name = result["name"] as? String , name == deviceName else {
                    return false
                }
            }
            if notificationService != nil || notificationToken != nil {
                guard let pushCredentials = result["push_credentials"] as? [String: String] else {
                    return false
                }
                if let notificationService = notificationService {
                    guard let service = pushCredentials["service"] , service == notificationService else {
                        return false
                    }
                }
                if let notificationToken = notificationToken {
                    guard let token = pushCredentials["token"] , token == notificationToken else {
                        return false
                    }
                }
            }
            return true
        }
        return false
    }
}

func haveEnrollment(withBaseUrl baseURL: URL, enrollmentId: String, deviceToken: String, notificationToken: String, issuer: String, userId: String, signingKey: RSAPrivateKey, base32Secret: String, algorithm: String, digits: Int, period: Int) -> MatcherFunc<Result<Enrollment>> {
    return MatcherFunc { expression, failureMessage in
        failureMessage.postfixMessage = "be an enrollment with" +
            " <baseUrl: \(baseURL)>" +
            " <id: \(enrollmentId)>" +
            " <deviceToken: \(deviceToken)>" +
            " <notificationToken: \(notificationToken)>" +
            " <issuer: \(issuer)>" +
            " <userId: \(userId)>" +
            " <signingKey: \(signingKey)>" +
            " <base32Secret: \(base32Secret)>" +
            " <algorithm: \(algorithm)>" +
            " <digits: \(digits)>" +
            " <period: \(period)>"
        
        if let actual = try expression.evaluate(), case .success(let result) = actual {
            return result.id == enrollmentId
                && result.userId == userId
                && result.deviceToken == deviceToken
                && result.notificationToken == notificationToken
                && result.signingKey.tag == signingKey.tag
                && result.base32Secret == base32Secret
                && result.algorithm == algorithm
                && result.digits == digits
                && result.period == period
        }
        return false
    }
}

func haveGuardianError<T>(withErrorCode errorCode: String? = nil, andStatusCode statusCode: Int? = nil) -> MatcherFunc<Result<T>> {
    return MatcherFunc { expression, failureMessage in
        var message = "be a Guardian error response with"
        if let errorCode = errorCode {
            message = message.appending(" <errorCode: \(errorCode)>")
        }
        if let statusCode = statusCode {
            message = message.appending(" <statusCode: \(statusCode)>")
        }
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .failure(let cause) = actual {
            if let error = cause as? GuardianError {
                return (errorCode == nil || errorCode == error.errorCode) &&
                (statusCode == nil || statusCode == error.statusCode)
            }
        }
        return false
    }
}

func haveNSError<T>(withErrorCode errorCode: Int? = nil) -> MatcherFunc<Result<T>> {
    return MatcherFunc { expression, failureMessage in
        var message = "be an NSError"
        if let errorCode = errorCode {
            message = message.appending(" with <code: \(errorCode)>")
        }
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .failure(let cause) = actual {
            let error = cause as NSError
            return errorCode == nil || errorCode == error.code
        }
        return false
    }
}

func haveError<T, E>(_ error: E) -> MatcherFunc<Result<T>> where E: Error, E: Equatable {
    return MatcherFunc { expression, failureMessage in
        let message = "fail with <error: \(error)>"
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .failure(let cause) = actual {
            if let cause = cause as? E {
                return cause == error
            }
        }
        return false
    }
}

func beSuccess(withData data: [String: String]) -> MatcherFunc<Result<[String: String]>> {
    return MatcherFunc { expression, failureMessage in
        let message = "be a success response with <payload: \(data)>"
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .success(let payload) = actual {
            return data == payload
        }
        return false
    }
}

func beSuccess<T>() -> MatcherFunc<Result<T>> {
    return MatcherFunc { expression, failureMessage in
        let message = "be an empty success response"
        failureMessage.postfixMessage = message
        if let actual = try expression.evaluate(), case .success(_) = actual {
            return true
        }
        return false
    }
}

extension URLRequest {
    var a0_payload: [String: Any]? {
        guard let data = (self as NSURLRequest).ohhttpStubs_HTTPBody() else { return nil }
        let object = try? JSONSerialization.jsonObject(with: data, options: [])
        return object as? [String: Any]
    }
}
