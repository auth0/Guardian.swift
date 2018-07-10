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

public let AuthenticationCategory = "com.auth0.notification.authentication"
public let acceptActionIdentifier: String = "\(AuthenticationCategory).accept"
public let rejectActionIdentifier: String = "\(AuthenticationCategory).reject"

/**
 A Guardian Notification contains data about an authentication request.
 
 You get one of this from the push notification data, for example in your 
 `AppDelegate` you should have something like this:

 ```
 func application(application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any]) {
    if let notification = Guardian.notification(from: userInfo) {
        // the push notification is a Guardian authentication request
        // do something with it
        print(notification)
    }
 }
 ```
 */
@objc(A0GNotification)
public protocol Notification {

    /**
     The Guardian server that sent the notification
     */
    var domain: String { get }

    /**
     The id of the Guardian `Enrollment`
     */
    var enrollmentId: String { get }

    /**
     The transaction token, used to identify the authentication request
     */
    var transactionToken: String { get }

    /**
     The challenge sent by the server. The same challenge, signed, should be 
     sent back when trying to allow or reject an authentication request
     */
    var challenge: String { get }

    /**
     The source (Browser & OS) where the authentication request was initiated,
     if available
     */
    var source: Source? { get }

    /**
     The location where the request was initiated, if available
     */
    var location: Location? { get }

    /**
     The date/time when the authentication request was initiated
     */
    var startedAt: Date { get }
}

/**
 The source (Browser & OS) of an authentication request
 */
@objc(A0GSource)
public protocol Source {

    /**
     The operating system data, if available
     */
    var os: OS? { get }

    /**
     The browser data, if available
     */
    var browser: Browser? { get }
}

/**
 The browser data of an authentication request
 */
@objc(A0GBrowser)
public protocol Browser {

    /**
     The name of the browser
     */
    var name: String { get }

    /**
     The version of the browser, if available
     */
    var version: String? { get }
}

/**
 The OS data of an authentication request
 */
@objc(A0GOS)
public protocol OS {

    /**
     The name of the operating system
     */
    var name: String { get }

    /**
     The version of the operating system, if available
     */
    var version: String? { get }
}

/**
 The geographical location of an authentication request
 */
@objc(A0GLocation)
public protocol Location {

    /**
     The name of the (approximate) location, if available
     */
    var name: String? { get }

    /**
     The approximate latitude, if available
     */
    var latitude: NSNumber? { get }

    /**
     The approximate longitude, if available
     */
    var longitude: NSNumber? { get }
}

class AuthenticationNotification: NSObject, Notification {

    let domain: String
    let enrollmentId: String
    let transactionToken: String
    let challenge: String
    let source: Source?
    let location: Location?
    let startedAt: Date

    @objc init(domain: String, enrollmentId: String, transactionToken: String, challenge: String, startedAt: Date, source: Source?, location: Location?) {
        self.domain = domain
        self.enrollmentId = enrollmentId
        self.transactionToken = transactionToken
        self.challenge = challenge
        self.source = source
        self.location = location
        self.startedAt = startedAt
    }

    @objc convenience init?(userInfo: [AnyHashable: Any]) {
        guard
            let json = userInfo as? [String: Any],
            let aps = json["aps"] as? [String: Any],
            let category = aps["category"] as? String, category == AuthenticationCategory
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

    override var description: String {
        return "enrollmentId: <\(self.enrollmentId)> txToken: <\(self.transactionToken)> challenge: <\(self.challenge)> startedAt: \(self.startedAt)"
    }

    override var debugDescription: String {
        return "domain: <\(self.domain)> enrollmentId: <\(self.enrollmentId)> txToken: <\(self.transactionToken)> challenge: <\(self.challenge)> source: <\(String(describing: self.source))> location: <\(String(describing: self.location))> startedAt: \(self.startedAt)"
    }
}

class AuthenticationSource: NSObject, Source {

    class NamedSource: NSObject, OS, Browser {
        let name: String
        let version: String?

        @objc init(name: String, version: String?) {
            self.name = name
            self.version = version
        }
    }

    let os: OS?
    let browser: Browser?

    @objc init?(fromJSON json: Any?) {
        guard let source = json as? [String: Any] else {
            return nil
        }

        let browser: Browser?
        let os: OS?
        if let data = source["b"] as? [String: Any], let name = data["n"] as? String {
            let version = data["v"] as? String
            browser = NamedSource(name: name, version: version)
        } else {
            browser = nil
        }
        if let data = source["os"] as? [String: Any], let name = data["n"] as? String {
            let version = data["v"] as? String
            os = NamedSource(name: name, version: version)
        } else {
            os = nil
        }

        if os == nil && browser == nil {
            return nil
        }
        self.os = os
        self.browser = browser
    }

    override var description: String {
        let osName = self.os?.name ?? "Unknown OS"
        let osVersion = self.os?.version != nil ? "(\(String(describing: self.os?.version))" : ""
        let browserName = self.browser?.name ?? "Unknown Browser"
        let browserVersion = self.browser?.version != nil ? "(\(String(describing: self.browser?.version))" : ""
        return "\(osName) \(osVersion)".trimmingCharacters(in: .whitespaces) + " \(browserName) \(browserVersion)".trimmingCharacters(in: .whitespaces)
    }

    override var debugDescription: String {
        return self.description
    }
}

class AuthenticationLocation: NSObject, Location {

    let name: String?
    let latitude: NSNumber?
    let longitude: NSNumber?

    @objc init?(fromJSON json: Any?) {
        guard let location = json as? [String: Any] else {
            return nil
        }

        name = location["n"] as? String
        let latitudeValue = location["lat"]
        let longitudeValue = location["long"]
        if let latitudeString = latitudeValue as? String,
            let longitudeString = longitudeValue as? String {
            latitude = Double(latitudeString) as NSNumber?
            longitude = Double(longitudeString) as NSNumber?
        } else {
            latitude = latitudeValue as? NSNumber
            longitude = longitudeValue as? NSNumber
        }
    }

    override var description: String {
        return "\(self.name ?? "Unknown") (\(String(describing: self.latitude)), \(String(describing: self.longitude)))"
    }

    override var debugDescription: String {
        return self.description
    }

}
