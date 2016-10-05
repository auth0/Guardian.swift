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

public func api(forDomain domain: String, session: NSURLSession = .sharedSession()) -> API {
    return APIClient(baseUrl: url(from: domain)!, session: session)
}

public func authentication(forDomain domain: String, andEnrollment enrollment: Enrollment, session: NSURLSession = .sharedSession()) -> Authentication {
    let client = api(forDomain: domain, session: session)
    return TOTPAuthentication(api: client, enrollment: enrollment)
}

public func enroll(forDomain domain: String, session: NSURLSession = .sharedSession(), usingUri uri: String, notificationToken: String) -> EnrollRequest {
    let client = api(forDomain: domain, session: session)
    return EnrollRequest(api: client, enrollmentUri: uri, notificationToken: notificationToken)
}

public func notification(from userInfo: [NSObject: AnyObject]) -> Notification? {
    return AuthenticationNotification(userInfo: userInfo)
}

func url(from domain: String) -> NSURL? {
    guard domain.hasPrefix("http") else { return NSURL(string: "https://\(domain)") }
    return NSURL(string: domain)
}
