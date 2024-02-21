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
import Nimble

@testable import Guardian

func isMobileEnroll(baseUrl: URL) -> MockURLProtocolCondition {
    return isScheme("https") && isMethodPOST() && isUrl(from: baseUrl, endingWithPathComponent: "api/enroll")
}

func isMethodPOST() -> MockURLProtocolCondition {
  return { $0.httpMethod == "POST" }
}

func isMethodDELETE() -> MockURLProtocolCondition {
  return { $0.httpMethod == "DELETE" }
}

func isMethodPATCH() -> MockURLProtocolCondition {
  return { $0.httpMethod == "PATCH" }
}

func isScheme(_ scheme: String) -> MockURLProtocolCondition {
  return { request in request.url?.scheme == scheme }
}

func isUrl(from baseUrl: URL, containingPathStartingWith path: String) -> MockURLProtocolCondition {
    return { req in
        let partialUrl = baseUrl.appendingPathComponent(path).absoluteString
        guard let url = req.url?.absoluteString,
            let range = url.range(of: partialUrl) else {
            return false
        }
        return range.lowerBound == path.startIndex
    }
}

func isUrl(from baseUrl: URL, endingWithPathComponent pathComponent: String) -> MockURLProtocolCondition {
    return { req in
        return req.url == baseUrl.appendingPathComponent(pathComponent)
    }
}

func hasTicketAuth(_ ticket: String) -> MockURLProtocolCondition {
    return { request in
        return request.value(forHTTPHeaderField: "Authorization") == "Ticket id=\"\(ticket)\""
    }
}

func hasAtLeast(_ parameters: [String: String]) -> MockURLProtocolCondition {
    return { request in
        guard let payload = request.a0_payload else { return false }
        let entries = parameters.filter { (key, _) in payload.contains { (name, _) in  key == name } }
        return entries.count == parameters.count && entries.reduce(true, { (initial, entry) -> Bool in
            return initial && payload[entry.0] as? String == entry.1
        })
    }
}

func hasField(_ field: String, withParameters parameters: [String: String]) -> MockURLProtocolCondition {
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

func isResolveTransaction(baseUrl: URL) -> MockURLProtocolCondition {
    return isScheme("https") && isMethodPOST() && isUrl(from: baseUrl, endingWithPathComponent: "api/resolve-transaction")
}

func hasBearerToken(_ token: String) -> MockURLProtocolCondition {
    return { request in
        return request.value(forHTTPHeaderField: "Authorization") == "Bearer \(token)"
    }
}

func isDeleteEnrollment(baseUrl: URL, enrollmentId: String? = nil) -> MockURLProtocolCondition {
    return isMethodDELETE() && isEnrollment(baseUrl: baseUrl, enrollmentId: enrollmentId)
}

func isEnrollment(baseUrl: URL, enrollmentId: String? = nil) -> MockURLProtocolCondition {
    if let enrollmentId = enrollmentId {
        return isUrl(from: baseUrl, endingWithPathComponent: "api/device-accounts/\(enrollmentId)")
    }
    return isUrl(from: baseUrl, containingPathStartingWith: "api/device-accounts/")
}

func hasBearerJWTToken(withSub sub: String, iss: String, aud: String, validFor duration: TimeInterval) -> MockURLProtocolCondition {
    return { request in
        guard let token = request.value(forHTTPHeaderField: "Authorization")?.split(separator: " ").last,
            let jwt = try? JWT<BasicClaimSet>(string: String(token)),
            let key = try? AsymmetricPublicKey(privateKey: DataRSAPrivateKey(data: Keys.shared.privateKey).secKey).secKey,
            (try? jwt.verify(with: key)) != nil else {
                return false
        }

        guard jwt.claimSet.subject == sub,
            jwt.claimSet.issuer == iss,
            jwt.claimSet.audience == aud,
            jwt.claimSet.expireAt.timeIntervalSince(jwt.claimSet.issuedAt) == duration else {
                return false
        }

        return true
    }
}

func isUpdateEnrollment(baseUrl: URL, enrollmentId: String? = nil) -> MockURLProtocolCondition {
    return isMethodPATCH() && isEnrollment(baseUrl: baseUrl, enrollmentId: enrollmentId)
}

func beUpdatedDevice(deviceIdentifier: String?, deviceName: String?, notificationService: String?, notificationToken: String?) -> Nimble.Predicate<Result<UpdatedDevice>> {
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

func haveEnrollment(withBaseUrl baseURL: URL, enrollmentId: String, deviceToken: String, notificationToken: String, issuer: String, userId: String, signingKey: SigningKey, base32Secret: String, algorithm: HMACAlgorithm, digits: Int, period: Int) -> Nimble.Predicate<Result<EnrolledDevice>> {
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

func haveGuardianError<T>(withErrorCode errorCode: String? = nil) -> Nimble.Predicate<Result<T>> {
    return Nimble.Predicate.define("be a Guardian error response with") { expression, msg -> PredicateResult in
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

extension URLRequest {
    var a0_payload: [String: Any]? {
        guard let bodyStream = self.httpBodyStream else { return nil }

        bodyStream.open()

        let bufferSize: Int = 16
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        var data = Data()

        while bodyStream.hasBytesAvailable {
            let readDat = bodyStream.read(buffer, maxLength: bufferSize)
            data.append(buffer, count: readDat)
        }

        buffer.deallocate()
        bodyStream.close()

        let jsonObject = try? JSONSerialization.jsonObject(with: data, options: JSONSerialization.ReadingOptions.allowFragments)
        return  jsonObject as? [String : Any]
    }
}


func beSuccess<T: Equatable>(with payload: T) -> Nimble.Predicate<Result<T>> {
    return Predicate.define("be a success result with \(payload)") { exp, msg in
        guard let result = try exp.evaluate(), case .success(let actual) = result else {
            return PredicateResult(status: .doesNotMatch, message: msg)
        }
        return PredicateResult(bool: actual == payload, message: msg)
    }
}

func beSuccess<T>() -> Nimble.Predicate<Result<T>> {
    return Predicate.define("be a success result of \(T.self)") { exp, msg in
        guard let result = try exp.evaluate(), case .success = result else {
            return PredicateResult(status: .doesNotMatch, message: msg)
        }
        return PredicateResult(status: .matches, message: msg)
    }
}

func beFailure<T>() -> Nimble.Predicate<Result<T>> {
    return Predicate.define("be a failure result of network operation") { exp, msg in
        guard let result = try exp.evaluate(), case .failure = result else {
            return PredicateResult(status: .doesNotMatch, message: msg)
        }
        return PredicateResult(status: .matches, message: msg)
    }
}

func beFailure<T>(with cause: MockError) -> Nimble.Predicate<Result<T>> {
    return Predicate.define("be a failure result of network operation w/ error \(cause)") { exp, msg in
        guard let result = try exp.evaluate(),
            case .failure(let actual) = result,
            let error = actual as? MockError else {
                return PredicateResult(status: .doesNotMatch, message: msg)
        }
        return PredicateResult(bool: error == cause, message: msg)
    }
}

func beFailure<T>(with cause: NetworkError) -> Nimble.Predicate<Result<T>> {
    return Predicate.define("be a failure result of network operation w/ error \(cause)") { exp, msg in
        guard let result = try exp.evaluate(),
            case .failure(let actual) = result,
            let error = actual as? NetworkError else {
                return PredicateResult(status: .doesNotMatch, message: msg)
        }
        return PredicateResult(bool: error == cause, message: msg)
    }
}
