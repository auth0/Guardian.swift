// AuthenticationNotification.swift
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

struct AuthenticationNotification {

    let domain: String
    let enrollmentId: String
    let transactionToken: String
    let source: Source?
    let locationName: String?
    let latitude: Double?
    let longitude: Double?
    let startedAt: NSDate

    init?(userInfo: [NSObject: AnyObject]) {
        guard
            let json = userInfo as? [String:AnyObject],
            let aps = json["aps"] as? [String:AnyObject],
            let category = aps["category"] as? String where category == NotificationService.AuthenticationCategory
            else {
                return nil
        }
        let locale = NSLocale(localeIdentifier: "en_US_POSIX")
        let formatter = NSDateFormatter()
        formatter.locale = locale
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        guard
            let mfa = json["mfa"] as? [String:AnyObject],
            let enrollmentId = mfa["dai"] as? String,
            let token = mfa["txtkn"] as? String,
            let when = mfa["d"] as? String,
            let startedAt = formatter.dateFromString(when),
            let domain = mfa["sh"] as? String
            else {
                return nil
        }
        var browserName: String?
        var browserVersion: String?
        var osName: String?
        var osVersion: String?
        if let source = mfa["s"] as? [String:AnyObject] {
            if let browser = source["b"] as? [String:AnyObject] {
                browserName = browser["n"] as? String
                browserVersion = browser["v"] as? String
            }
            if let os = source["os"] as? [String:AnyObject] {
                osName = os["n"] as? String
                osVersion = os["v"] as? String
            }
        }
        var locationName: String?
        var latitude: Double?
        var longitude: Double?
        if let location = mfa["l"] as?  [String:AnyObject] {
            locationName = location["n"] as? String
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

        self.domain = domain
        self.enrollmentId = enrollmentId
        self.transactionToken = token
        self.locationName = locationName
        self.startedAt = startedAt

        if browserName != nil || osName != nil {
            self.source = Source(osName: osName, osVersion: osVersion, browserName: browserName, browserVersion: browserVersion)
        } else {
            self.source = nil
        }

        self.latitude = latitude
        self.longitude = longitude
    }
}

struct Source {

    let osName: String?
    let osVersion: String?
    let browserName: String?
    let browserVersion: String?

    var browser: (name: String, version: String?)? {
        guard let name = browserName else {
            return nil
        }
        return (name: name, version: browserVersion)
    }

    var os: (name: String, version: String?)? {
        guard let name = osName else {
            return nil
        }
        return (name: name, version: osVersion)
    }
}

class NotificationService {

    static let AuthenticationCategory = "com.auth0.notification.authentication"
    static let AuthenticationAcceptAction = "\(NotificationService.AuthenticationCategory).accept"
    static let AuthenticationRejectAction = "\(NotificationService.AuthenticationCategory).reject"
}
