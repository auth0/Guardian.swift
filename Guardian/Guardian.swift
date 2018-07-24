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

/// Default URLSession used to send requests to Guardian API.
public let defaultURLSession: URLSession =  {
    let config = URLSessionConfiguration.default
    config.requestCachePolicy = .reloadIgnoringLocalCacheData
    config.urlCache = nil

    return URLSession.init(configuration: config)
}()

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
public func api(forDomain domain: String, session: URLSession = defaultURLSession) -> API {
    return api(url: url(from: domain)!, session: session)
}

/**
 Creates a low level API client for Guardian MFA server

 ```
 let api = Guardian.api(url: URL(string: "https://tenant.guardian.auth0.com/")!)
 ```

 - parameter url:       URL of your Guardian server
 - parameter session:   session to use for network requests

 - returns: an Guardian API client

 - seealso: Guardian.API
 */
public func api(url: URL, session: URLSession = defaultURLSession) -> API {
    return APIClient(baseUrl: url, session: session)
}

/**
 Creates an authentication manager for a Guardian enrollment

 ```
 let enrollment: Enrollment = // the object you obtained when enrolling
 let authenticator = Guardian
    .authentication(forDomain: "tenant.guardian.auth0.com", andEnrollment: enrollment)
 ```

 - parameter forDomain:     domain or URL of your Guardian server
 - parameter device:        the enrolled device that will be used to handle authentication
 - parameter session:       session to use for network requests
 
 - returns: an `Authentication` instance
 
 - seealso: Guardian.Authentication
 */
public func authentication(forDomain domain: String, device: AuthenticationDevice, session: URLSession = defaultURLSession) -> Authentication {
    let client = api(forDomain: domain, session: session)
    return RSAAuthentication(api: client, device: device)
}

/**
 Creates an authentication manager for a Guardian enrollment

 ```
 let enrollment: Enrollment = // the object you obtained when enrolling
 let authenticator = Guardian
    .authentication(url: URL(string: "https://tenant.guardian.auth0.com/")!,
                    andEnrollment: enrollment)
 ```

 - parameter url:           URL of your Guardian server
 - parameter device:        the enrolled device that will be used to handle authentication
 - parameter session:       session to use for network requests

 - returns: an `Authentication` instance

 - seealso: Guardian.Authentication
 */
public func authentication(url: URL, device: AuthenticationDevice, session: URLSession = defaultURLSession) -> Authentication {
    let client = api(url: url, session: session)
    return RSAAuthentication(api: client, device: device)
}

/**
 Creates a request to enroll from a Guardian enrollment URI
 
 You'll have to create a new pair of RSA keys for the enrollment.
 The keys will be stored on the keychain, and we'll later access them by `tag`,
 so you should use a unique identifier every time you create them.

 ```
 let rsaKeyPair = RSAKeyPair.new(usingPublicTag: "com.auth0.guardian.enroll.public",
                                 privateTag: "com.auth0.guardian.enroll.private")
 ```

 You will also need an enroll uri (from a Guardian QR code for example) and the 
 APNS token for the device.

 Finally, to create an enrollment you just use it like this:

 ```
 let enrollUri: String = // obtained from a Guardian QR code
 let apnsToken: String = // apple push notification service token for this device

 Guardian
    .enroll(forDomain: "tenant.guardian.auth0.com",
            usingUri: enrollUri,
            notificationToken: apnsToken,
            keyPair: rsaKeyPair)
    .start { result in
        switch result {
        case .success(let enrollment):
            // we have the enrollment data, save it for later usages
        case .failure(let cause):
            // something failed
        }
 }
 ```

 - parameter forDomain:         domain or URL of your Guardian server
 - parameter session:           session to use for network requests
 - parameter usingUri:          the enrollment URI
 - parameter notificationToken: the APNS token of the device
 - parameter signingKey:        the signing key for Guardian AuthN responses
 - parameter signingKey:        the verification key for Guardian AuthN responses
 
 - returns: a request to create an enrollment
 */
public func enroll(forDomain domain: String, session: URLSession = defaultURLSession, usingUri uri: String, notificationToken: String, signingKey: SigningKey, verificationKey: VerificationKey) -> EnrollRequest {
    let client = api(forDomain: domain, session: session)
    return EnrollRequest(api: client, enrollmentUri: uri, notificationToken: notificationToken, verificationKey: verificationKey, signingKey: signingKey)
}

/**
 Creates a request to enroll from a Guardian enrollment URI

 You'll have to create a new pair of RSA keys for the enrollment.
 The keys will be stored on the keychain, and we'll later access them by `tag`,
 so you should use a unique identifier every time you create them.

 ```
 let rsaKeyPair = RSAKeyPair.new(usingPublicTag: "com.auth0.guardian.enroll.public",
                                 privateTag: "com.auth0.guardian.enroll.private")
 ```

 You will also need an enroll uri (from a Guardian QR code for example) and the
 APNS token for the device.

 Finally, to create an enrollment you just use it like this:

 ```
 let enrollUri: String = // obtained from a Guardian QR code
 let apnsToken: String = // apple push notification service token for this device

 Guardian
    .enroll(url: URL(string: "https://tenant.guardian.auth0.com/")!,
            usingUri: enrollUri,
            notificationToken: apnsToken,
            keyPair: rsaKeyPair)
    .start { result in
        switch result {
        case .success(let enrollment):
            // we have the enrollment data, save it for later usages
        case .failure(let cause):
            // something failed
        }
 }
 ```

 - parameter url:               URL of your Guardian server
 - parameter session:           session to use for network requests
 - parameter usingUri:          the enrollment URI
 - parameter notificationToken: the APNS token of the device
 - parameter signingKey:        the signing key for Guardian AuthN responses
 - parameter signingKey:        the verification key for Guardian AuthN responses

 - returns: a request to create an enrollment
 */
public func enroll(url: URL, session: URLSession = defaultURLSession, usingUri uri: String, notificationToken: String, signingKey: SigningKey, verificationKey: VerificationKey) -> EnrollRequest {
    let client = api(url: url, session: session)
    return EnrollRequest(api: client, enrollmentUri: uri, notificationToken: notificationToken, verificationKey: verificationKey, signingKey: signingKey)
}

/**
 Creates a request to enroll from a Guardian enrollment ticket

 You'll have to create a new pair of RSA keys for the enrollment.
 The keys will be stored on the keychain, and we'll later access them by `tag`, 
 so you should use a unique identifier every time you create them.

 ```
 let rsaKeyPair = RSAKeyPair.new(usingPublicTag: "com.auth0.guardian.enroll.public",
                                 privateTag: "com.auth0.guardian.enroll.private")
 ```

 You will also need an enroll ticket and the APNS token for the device.

 Finally, to create an enrollment you just use it like this:

 ```
 let enrollTicket: String = // obtained from a Guardian QR code or email
 let apnsToken: String = // apple push notification service token for this device

 Guardian
    .enroll(forDomain: "tenant.guardian.auth0.com",
            usingTicket: enrollTicket,
            notificationToken: apnsToken,
            keyPair: rsaKeyPair)
    .start { result in
        switch result {
        case .success(let enrollment):
            // we have the enrollment data, save it for later usages
        case .failure(let cause):
            // something failed
        }
 }
 ```

 - parameter forDomain:         domain or URL of your Guardian server
 - parameter session:           session to use for network requests
 - parameter usingTicket:       the enrollment ticket
 - parameter notificationToken: the APNS token of the device
 - parameter signingKey:        the signing key for Guardian AuthN responses
 - parameter signingKey:        the verification key for Guardian AuthN responses

 - returns: a request to create an enrollment
 */
public func enroll(forDomain domain: String, session: URLSession = defaultURLSession, usingTicket ticket: String, notificationToken: String, signingKey: SigningKey, verificationKey: VerificationKey) -> EnrollRequest {
    let client = api(forDomain: domain, session: session)
    return EnrollRequest(api: client, enrollmentTicket: ticket, notificationToken: notificationToken, verificationKey: verificationKey, signingKey: signingKey)
}

/**
 Creates a request to enroll from a Guardian enrollment ticket

 You'll have to create a new pair of RSA keys for the enrollment.
 The keys will be stored on the keychain, and we'll later access them by `tag`,
 so you should use a unique identifier every time you create them.

 ```
 let rsaKeyPair = RSAKeyPair.new(usingPublicTag: "com.auth0.guardian.enroll.public",
                                 privateTag: "com.auth0.guardian.enroll.private")
 ```

 You will also need an enroll ticket and the APNS token for the device.

 Finally, to create an enrollment you just use it like this:

 ```
 let enrollTicket: String = // obtained from a Guardian QR code or email
 let apnsToken: String = // apple push notification service token for this device

 Guardian
    .enroll(url: URL(string: "https://tenant.guardian.auth0.com/")!,
            usingTicket: enrollTicket,
            notificationToken: apnsToken,
            keyPair: rsaKeyPair)
    .start { result in
        switch result {
        case .success(let enrollment):
            // we have the enrollment data, save it for later usages
        case .failure(let cause):
            // something failed
        }
 }
 ```

 - parameter url:               URL of your Guardian server
 - parameter session:           session to use for network requests
 - parameter usingTicket:       the enrollment ticket
 - parameter notificationToken: the APNS token of the device
 - parameter signingKey:        the signing key for Guardian AuthN responses
 - parameter signingKey:        the verification key for Guardian AuthN responses

 - returns: a request to create an enrollment
 */
public func enroll(url: URL, session: URLSession = defaultURLSession, usingTicket ticket: String, notificationToken: String, signingKey: SigningKey, verificationKey: VerificationKey) -> EnrollRequest {
    let client = api(url: url, session: session)
    return EnrollRequest(api: client, enrollmentTicket: ticket, notificationToken: notificationToken, verificationKey: verificationKey, signingKey: signingKey)
}

/**
 Parses and returns the data about the push notification's authentication
 request.
 
 You should use this method in your `AppDelegate`, for example like this:
 
 ```
 func application(application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable : Any]) {
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
public func notification(from userInfo: [AnyHashable: Any]) -> Notification? {
    return AuthenticationNotification(userInfo: userInfo)
}

func url(from domain: String) -> URL? {
    guard domain.hasPrefix("http") else { return URL(string: "https://\(domain)") }
    return URL(string: domain)
}
