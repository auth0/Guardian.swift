// AuthenticationCategory.swift
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

/**
 Stores the default Guardian Push notification category and actions identifiers.
 With these values you can create the `UNNotificationCategory` and `UNNotificationAction` to register
 when notification access is requested using the UserNotification.framework.

 ````
 let guardianCategory = Guardian.AuthenticationCategory.default

 // Set up guardian notifications actions
 let acceptAction = UNNotificationAction(
     identifier: guardianCategory.allow.identifier,
     title: NSLocalizedString("Allow", comment: "Accept Guardian authentication request"),
     options: [.authenticationRequired] // Always request local AuthN
 )
 let rejectAction = UNNotificationAction(
     identifier: guardianCategory.reject.identifier,
     title: NSLocalizedString("Deny", comment: "Reject Guardian authentication request"),
     options: [.destructive, .authenticationRequired] // Always request local AuthN
 )

 // Set up guardian notification category
 let category = UNNotificationCategory(
     identifier: guardianCategory.identifier,
     actions: [acceptAction, rejectAction],
     intentIdentifiers: [],
     options: []
 )

 // Request for AuthZ
 UNUserNotificationCenter.current().requestAuthorization(options: [.badge, .sound]) { granted, error in
    guard granted else {
        return print("Permission not granted")
    }
    if let error = error {
        return print("failed with error \(error)")
    }

    // Register guardian notification category
    UNUserNotificationCenter.current().setNotificationCategories([category])

    // Check AuthZ status to trigger remote notification registration
    UNUserNotificationCenter.current().getNotificationSettings() { settings in
        guard settings.authorizationStatus == .authorized else {
            return print("not authorized to use notifications")
        }
        DispatchQueue.main.async { application.registerForRemoteNotifications() }
    }
 }
 ```

 Then in your User notification delegate, handle the notification action using the identifier provided by iOS

 ```
 func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
    let identifier = response.actionIdentifier
    let userInfo = response.notification.request.content.userInfo
    if let notification = Guardian.notification(from: userInfo) {
        /* Get the enrollment that matches the notification ... */
        let enrollment: Enrollment = ...
        Guardian
        .authentication(forDomain: "tenant.guardian.auth0.com", andEnrollment: enrollment)
        .handleAction(withIdentifier: identifier, notification: notification)
        .start { result in
            completionHandler()
        }
    } else {
    // Other type of notification
    completionHandler()
    }
 }
 ```
 */
public struct AuthenticationCategory {

    /**
    Represents one possible action of the Guardian Notification
    */
    public struct Action: Equatable {
        /// Identifier of the action, composed of _{category_id}.{name}_
        public let identifier: String
    }

    /// Identifier of the category
    public let identifier: String
    /// allow action
    public let allow: Action
    /// reject action
    public let reject: Action

    private init(identifier: String) {
        self.identifier = identifier
        self.allow = Action(identifier: "\(self.identifier).accept")
        self.reject = Action(identifier: "\(self.identifier).reject")
    }

    private static let defaultIdentifier = "com.auth0.notification.authentication"

    /// The default guardian category for notifications. It also provides the default actions
    public static var `default`: AuthenticationCategory {
        return AuthenticationCategory(identifier: defaultIdentifier)
    }
}
