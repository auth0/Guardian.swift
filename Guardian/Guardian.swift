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
public func api(forDomain domain: String, session: URLSession = .shared) -> API {
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
public func authentication(forDomain domain: String, andEnrollment enrollment: Enrollment, session: URLSession = .shared) -> Authentication {
    let client = api(forDomain: domain, session: session)
    return RSAAuthentication(api: client, enrollment: enrollment)
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
 - parameter keyPair:           the RSA key pair
 
 - returns: a request to create an enrollment
 */
public func enroll(forDomain domain: String, session: URLSession = .shared, usingUri uri: String, notificationToken: String, keyPair: RSAKeyPair) -> EnrollRequest {
    let client = api(forDomain: domain, session: session)
    return EnrollRequest(api: client, enrollmentUri: uri, notificationToken: notificationToken, keyPair: keyPair)
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
 - parameter keyPair:           the RSA key pair

 - returns: a request to create an enrollment
 */
public func enroll(forDomain domain: String, session: URLSession = .shared, usingTicket ticket: String, notificationToken: String, keyPair: RSAKeyPair) -> EnrollRequest {
    let client = api(forDomain: domain, session: session)
    return EnrollRequest(api: client, enrollmentTicket: ticket, notificationToken: notificationToken, keyPair: keyPair)
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

/**
 Creates the `UIUserNotificationCategory` for Guardian using the provided action
 titles.

 Use this method to set up your application to receive and handle Guardian push 
 notifications.
 
 Should be called in your AppDelegate's `application(:didFinishLaunchingWithOptions)` method:
 
 ```
 func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]?) -> Bool {
    /* ... */

    // Set up push notifications
    let category = Guardian.categoryForNotification(withAcceptTitle: NSLocalizedString("Allow", comment: "Accept Guardian authentication request"),
                                                    rejectTitle: NSLocalizedString("Deny", comment: "Reject Guardian authentication request"))
    let notificationTypes: UIUserNotificationType = [.badge, .sound]
    let pushNotificationSettings = UIUserNotificationSettings(types: notificationTypes, categories: [category])
    application.registerUserNotificationSettings(pushNotificationSettings)
    application.registerForRemoteNotifications()
 
    /* ... */
    return true
 }
 ```

 Remember that you should also override your `application(:handleActionWithIdentifier:forRemoteNotification:withResponseInfo:completionHandler)`
 method to automatically handle the notification actions:
 
 ```
 func application(_ application: UIApplication, handleActionWithIdentifier identifier: String?, forRemoteNotification userInfo: [AnyHashable : Any], withResponseInfo responseInfo: [AnyHashable : Any], completionHandler: @escaping () -> Void) {
    if let notification = Guardian.notification(from: userInfo) {
        /* Get the enrollment that matches the notification ... */
        let enrollment: Enrollment = ...
        Guardian
            .authentication(forDomain: "tenant.guardian.auth0.com", andEnrollment: enrollment)
            .handleAction(withIdentifier: identifier, notification: notification)
            .start { result in
                completionHandler()
        }
    }
 }
 ```
 
 - parameter withAcceptTitle: the title for the "Accept" notification action
 - parameter rejectTitle:     the title for the "Reject" notification action
 */
public func categoryForNotification(withAcceptTitle acceptTitle: String, rejectTitle: String) -> UIUserNotificationCategory {
    let acceptAction = UIMutableUserNotificationAction()
    acceptAction.identifier = acceptActionIdentifier
    acceptAction.title = acceptTitle
    acceptAction.isAuthenticationRequired = true
    acceptAction.activationMode = .background
    acceptAction.isDestructive = false

    let rejectAction = UIMutableUserNotificationAction()
    rejectAction.identifier = rejectActionIdentifier
    rejectAction.title = rejectTitle
    rejectAction.isAuthenticationRequired = true
    rejectAction.activationMode = .background
    rejectAction.isDestructive = true

    let category = UIMutableUserNotificationCategory()
    category.identifier = AuthenticationCategory
    category.setActions([acceptAction, rejectAction], for: .default)
    category.setActions([acceptAction, rejectAction], for: .minimal)

    return category
}

func url(from domain: String) -> URL? {
    guard domain.hasPrefix("http") else { return URL(string: "https://\(domain)") }
    return URL(string: domain)
}
