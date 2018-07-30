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

func haveDeviceAccountToken(_ deviceAccountToken: String?) -> Predicate<Result<[String: String]>> {
    return Predicate.define("be a successful enrollment info result with") { actualExpression, msg -> PredicateResult in
        let message = msg.appended(details: String(describing: deviceAccountToken))
        if let actual = try actualExpression.evaluate(), case .success(let result) = actual {
            if let token = result["device_account_token"] {
                return PredicateResult(status: PredicateStatus(bool: deviceAccountToken == token), message: message)
            }
        }
        return PredicateResult(status: .fail, message: message)
    }
}

func beUpdatedDevice(deviceIdentifier: String?, deviceName: String?, notificationService: String?, notificationToken: String?) -> Predicate<Result<UpdatedDevice>> {
    return Predicate.define("be a updated device result with") { expression, msg -> PredicateResult in
        var message = msg
        if let deviceIdentifier = deviceIdentifier {
            message = message.appended(details: " <identifier: \(deviceIdentifier)>")
        }
        if let deviceName = deviceName {
            message = message.appended(details: " <name: \(deviceName)>")
        }
        if let notificationService = notificationService {
            message = message.appended(details: " <push_credentials.service: \(notificationService)>")
        }
        if let notificationToken = notificationToken {
            message = message.appended(details: " <push_credentials.token: \(notificationToken)>")
        }

        if let actual = try expression.evaluate(), case .success(let result) = actual {
            if let deviceIdentifier = deviceIdentifier {
                guard result.identifier == deviceIdentifier else {
                    return PredicateResult(status: .fail, message: message)
                }
            }
            if let deviceName = deviceName {
                guard result.name == deviceName else {
                    return PredicateResult(status: .fail, message: message)
                }
            }
            if notificationService != nil || notificationToken != nil {
                guard let pushCredentials = result.pushCredentials else {
                    return PredicateResult(status: .fail, message: message)
                }
                if let notificationService = notificationService {
                    guard pushCredentials.service == notificationService else {
                        return PredicateResult(status: .fail, message: message)
                    }
                }
                if let notificationToken = notificationToken {
                    guard pushCredentials.token == notificationToken else {
                        return PredicateResult(status: .fail, message: message)
                    }
                }
            }
            return PredicateResult(status: PredicateStatus(bool: true), message: message)
        }
        return PredicateResult(status: .fail, message: message)

    }
}

func haveEnrollment(withBaseUrl baseURL: URL, enrollmentId: String, deviceToken: String, notificationToken: String, issuer: String, userId: String, signingKey: SigningKey, base32Secret: String, algorithm: HMACAlgorithm, digits: Int, period: Int) -> Predicate<Result<EnrolledDevice>> {
    return Predicate.define("be an enrollment with") { expression, msg -> PredicateResult in
        let message = msg.appended(details: " <baseUrl: \(baseURL)>" +
            " <id: \(enrollmentId)>" +
            " <deviceToken: \(deviceToken)>" +
            " <notificationToken: \(notificationToken)>" +
            " <issuer: \(issuer)>" +
            " <userId: \(userId)>" +
            " <signingKey: \(signingKey)>" +
            " <base32Secret: \(base32Secret)>" +
            " <algorithm: \(algorithm)>" +
            " <digits: \(digits)>" +
            " <period: \(period)>")
        if let actual = try expression.evaluate(), case .success(let result) = actual {
            let status = result.id == enrollmentId
                && result.userId == userId
                && result.deviceToken == deviceToken
                && result.notificationToken == notificationToken
                && result.signingKey.secKey == signingKey.secKey
                && result.totp?.base32Secret == base32Secret
                && result.totp?.algorithm == algorithm
                && result.totp?.digits == digits
                && result.totp?.period == period
            return PredicateResult(bool: status, message: message)
        }
        return PredicateResult(status: .fail, message: message)
    }
}

func haveGuardianError<T>(withErrorCode errorCode: String? = nil) -> Predicate<Result<T>> {
    return Predicate.define("be a Guardian error response with") { expression, msg -> PredicateResult in
        var message = msg
        if let errorCode = errorCode {
            message = message.appended(details: " <errorCode: \(errorCode)>")
        }
        if let actual = try expression.evaluate(), case .failure(let cause) = actual {
            if let error = cause as? GuardianError {
                let status = (errorCode == nil || errorCode == error.code)
                return PredicateResult(bool: status, message: message)
            }
        }
        return PredicateResult(status: .fail, message: message)
    }
}

func haveNSError<T>(withErrorCode errorCode: Int? = nil) -> Predicate<Result<T>> {
    return Predicate.define("be an NSError") { expression, msg -> PredicateResult in
        var message = msg
        if let errorCode = errorCode {
            message = message.appended(details: " with <code: \(errorCode)>")
        }
        if let actual = try expression.evaluate(), case .failure(let cause) = actual {
            let error = cause as NSError
            let status = errorCode == nil || errorCode == error.code
            return PredicateResult(bool: status, message: message)
        }
        return PredicateResult(status: .fail, message: message)
    }
}

func haveError<T, E>(_ error: E) -> Predicate<Result<T>> where E: Swift.Error, E: Equatable {
    return Predicate.define("fail with <error: \(error)>") { expression, msg -> PredicateResult in
        if let actual = try expression.evaluate(), case .failure(let cause) = actual {
            if let cause = cause as? E {
                return PredicateResult(bool: cause == error, message: msg)
            }
        }
        return PredicateResult(status: .fail, message: msg)
    }
}

func beSuccess(withData data: [String: String]) -> Predicate<Result<[String: String]>> {
    return Predicate.define("be a success response with <payload: \(data)>") { expression, msg -> PredicateResult in
        if let actual = try expression.evaluate(), case .success(let payload) = actual {
            return PredicateResult(bool: data == payload, message: msg)
        }
        return PredicateResult(status: .fail, message: msg)
    }
}

extension URLRequest {
    var a0_payload: [String: Any]? {
        guard let data = (self as NSURLRequest).ohhttpStubs_HTTPBody() else { return nil }
        let object = try? JSONSerialization.jsonObject(with: data, options: [])
        return object as? [String: Any]
    }
}
