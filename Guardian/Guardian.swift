// Guardian.swift
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

/**
 Creates a low level API client for Guardian MFA server

 ```
 let api = Guardian.api(forDomain: "tenant.guardian.auth0.com")
 ```

 - parameter forDomain: domain or URL of your Guardian server
 - parameter session:   session to use for network requests
 
 - returns: an Guardian API client
 
 - seealso: Guardian.API
 */
public func api(forDomain domain: String, session: NSURLSession = .sharedSession()) -> API {
    return APIClient(baseUrl: url(from: domain)!, session: session)
}

/**
 Creates an authentication manager for a Guardian enrollment

 ```
 let enrollment: Enrollment = // the object you obtained when enrolling
 let authenticator = Guardian
    .authentication(forDomain: "tenant.guardian.auth0.com", andEnrollment: enrollment)
 ```

 - parameter forDomain:     domain or URL of your Guardian server
 - parameter andEnrollment: the enrollment that will be used to handle 
                            authentication
 - parameter session:       session to use for network requests
 
 - returns: an `Authentication` instance
 
 - seealso: Guardian.Authentication
 */
public func authentication(forDomain domain: String, andEnrollment enrollment: Enrollment, session: NSURLSession = .sharedSession()) -> Authentication {
    let client = api(forDomain: domain, session: session)
    return TOTPAuthentication(api: client, enrollment: enrollment)
}

/**
 Creates a request to enroll from a Guardian enrollment URI
 
 ```
 let enrollUri: String = // obtained from a Guardian QR code
 let apnsToken: String = // apple push notification service token for this device
 Guardian
    .enroll(forDomain: "tenant.guardian.auth0.com",
            usingUri: enrollUri,
            notificationToken: apnsToken)
    .start { result in
        switch result {
        case .Success(let enrollment):
            // we have the enrollment data, save it for later usages
        case .Failure(let cause):
            // something failed
        }
 }
 ```

 - parameter forDomain:         domain or URL of your Guardian server
 - parameter session:           session to use for network requests
 - parameter usingUri:          the enrollment URI
 - parameter notificationToken: the APNS token of the device
 
 - returns: a request to create an enrollment
 */
public func enroll(forDomain domain: String, session: NSURLSession = .sharedSession(), usingUri uri: String, notificationToken: String) -> EnrollRequest {
    let client = api(forDomain: domain, session: session)
    return EnrollRequest(api: client, enrollmentUri: uri, notificationToken: notificationToken)
}

/**
 Parses and returns the data about the push notification's authentication 
 request.
 
 You should use this method in your `AppDelegate`, for example like this:
 
 ```
 func application(application: UIApplication, didReceiveRemoteNotification userInfo: [NSObject : AnyObject]) {
    if let notification = Guardian.notification(from: userInfo) {
        // the push notification is a Guardian authentication request
        // do something with it
        print(notification)
    }
 }
 ```

 - parameter from: the push notification payload
 
 - returns: a Notification instance, or nil when the push notification is not a 
            Guardian authentication request
 
 - seealso: Guardian.Notification
 */
public func notification(from userInfo: [NSObject: AnyObject]) -> Notification? {
    return AuthenticationNotification(userInfo: userInfo)
}

func url(from domain: String) -> NSURL? {
    guard domain.hasPrefix("http") else { return NSURL(string: "https://\(domain)") }
    return NSURL(string: domain)
}
