// Notification.swift
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

private let AuthenticationCategory = "com.auth0.notification.authentication"

public struct Notification {

    public let domain: String
    public let enrollmentId: String
    public let transactionToken: String
    public let source: Source?
    public let location: Location?
    public let startedAt: NSDate

    init(domain: String, enrollmentId: String, transactionToken: String, startedAt: NSDate, source: Source?, location: Location?) {
        self.domain = domain
        self.enrollmentId = enrollmentId
        self.transactionToken = transactionToken
        self.source = source
        self.location = location
        self.startedAt = startedAt
    }

    init?(userInfo: [NSObject: AnyObject]) {
        guard
            let json = userInfo as? [String: AnyObject],
            let aps = json["aps"] as? [String: AnyObject],
            let category = aps["category"] as? String where category == AuthenticationCategory
            else { return nil }
        let locale = NSLocale(localeIdentifier: "en_US_POSIX")
        let formatter = NSDateFormatter()
        formatter.locale = locale
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        guard
            let mfa = json["mfa"] as? [String: AnyObject],
            let enrollmentId = mfa["dai"] as? String,
            let token = mfa["txtkn"] as? String,
            let when = mfa["d"] as? String,
            let startedAt = formatter.dateFromString(when),
            let domain = mfa["sh"] as? String
            else { return nil }
        let source = Source(fromJSON: mfa["s"])
        let location = Location(fromJSON: mfa["l"])

        self.init(domain: domain, enrollmentId: enrollmentId, transactionToken: token, startedAt: startedAt, source: source, location: location)
    }
}

public struct Source {

    let osName: String?
    let osVersion: String?
    let browserName: String?
    let browserVersion: String?

    init?(fromJSON json: AnyObject?) {
        guard let source = json as? [String: AnyObject] else {
            return nil
        }
        if let browser = source["b"] as? [String: AnyObject] {
            browserName = browser["n"] as? String
            browserVersion = browser["v"] as? String
        } else {
            browserName = nil
            browserVersion = nil
        }
        if let os = source["os"] as? [String: AnyObject] {
            osName = os["n"] as? String
            osVersion = os["v"] as? String
        } else {
            osName = nil
            osVersion = nil
        }

        if browserName == nil && osName == nil {
            return nil
        }
    }

    public var browser: (name: String, version: String?)? {
        guard let name = browserName else {
            return nil
        }
        return (name: name, version: browserVersion)
    }

    public var os: (name: String, version: String?)? {
        guard let name = osName else {
            return nil
        }
        return (name: name, version: osVersion)
    }
}

public struct Location {

    public let name: String?
    public let latitude: Double?
    public let longitude: Double?

    init?(fromJSON json: AnyObject?) {
        guard let location = json as? [String: AnyObject] else {
            return nil
        }

        name = location["n"] as? String
        let latitudeValue = location["lat"]
        let longitudeValue = location["long"]
        if let latitudeString = latitudeValue as? String,
            let longitudeString = longitudeValue as? String {
            latitude = Double(latitudeString)
            longitude = Double(longitudeString)
        } else {
            latitude = latitudeValue as? Double
            longitude = longitudeValue as? Double
        }
    }
}
