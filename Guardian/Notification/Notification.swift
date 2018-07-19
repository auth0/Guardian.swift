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

/**
 A Guardian Notification contains data about an authentication request.
 
 You get one of this from the push notification data in your UserNotificationCenter delegate:

 ```
 if let notification = Guardian.notification(from: userInfo) {
    // the push notification is a Guardian authentication request
    // do something with it
    print(notification)
 }
 ```
 */
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
public protocol Location {

    /**
     The name of the (approximate) location, if available
     */
    var name: String? { get }

    /**
     The approximate latitude, if available
     */
    var latitude: Double? { get }

    /**
     The approximate longitude, if available
     */
    var longitude: Double? { get }
}
