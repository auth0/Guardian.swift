// AuthenticationNotification.swift
//
// Copyright (c) 2018 Auth0 (http://auth0.com)
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

struct AuthenticationNotification: Notification, CustomDebugStringConvertible, CustomStringConvertible {

    let domain: String
    let enrollmentId: String
    let transactionToken: String
    let challenge: String
    let source: Source?
    let location: Location?
    let startedAt: Date

    init(domain: String, enrollmentId: String, transactionToken: String, challenge: String, startedAt: Date, source: Source?, location: Location?) {
        self.domain = domain
        self.enrollmentId = enrollmentId
        self.transactionToken = transactionToken
        self.challenge = challenge
        self.source = source
        self.location = location
        self.startedAt = startedAt
    }

    init?(userInfo: [AnyHashable: Any]) {
        guard
            let json = userInfo as? [String: Any],
            let aps = json["aps"] as? [String: Any],
            let category = aps["category"] as? String, category == AuthenticationCategory.default.identifier
            else { return nil }
        let locale = Locale(identifier: "en_US_POSIX")
        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        guard
            let mfa = json["mfa"] as? [String: Any],
            let enrollmentId = mfa["dai"] as? String,
            let token = mfa["txtkn"] as? String,
            let when = mfa["d"] as? String,
            let startedAt = formatter.date(from: when),
            let domain = mfa["sh"] as? String,
            let challenge = mfa["c"] as? String
            else { return nil }
        let source = AuthenticationSource(fromJSON: mfa["s"])
        let location = AuthenticationLocation(fromJSON: mfa["l"])

        self.init(domain: domain, enrollmentId: enrollmentId, transactionToken: token, challenge: challenge, startedAt: startedAt, source: source, location: location)
    }

    var description: String {
        return "enrollmentId: <\(self.enrollmentId)> txToken: <\(self.transactionToken)> challenge: <\(self.challenge)> startedAt: \(self.startedAt)"
    }

    var debugDescription: String {
        return "domain: <\(self.domain)> enrollmentId: <\(self.enrollmentId)> txToken: <\(self.transactionToken)> challenge: <\(self.challenge)> source: <\(String(describing: self.source))> location: <\(String(describing: self.location))> startedAt: \(self.startedAt)"
    }
}
