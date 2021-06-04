// AppDelegate.swift
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

import UIKit
import Guardian
import UserNotifications

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    static let guardianDomain = "guardian-demo.guardian.auth0.com"
    static var pushToken: String? = nil
    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]?) -> Bool {

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
            options: [])

        // Request for AuthZ
        UNUserNotificationCenter.current().delegate = self
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

        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        // when the registration for push notification succeeds
        let token = deviceToken.reduce(String(), {$0 + String(format: "%02X", $1)})
        AppDelegate.pushToken = token
        print("DEVICE TOKEN = \(token)")
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Swift.Error) {
        // when there's an error and the registration for push notifications failed
        print(error)
    }

    var rootController: UIViewController? {
        return window?.rootViewController
    }
}

extension AppDelegate {
    static var state: GuardianState? {
        get {
            return GuardianState.load()
        }
        set {
            if newValue == nil {
                GuardianState.delete()
            } else {
                try? newValue?.save()
            }
        }
    }
}

extension AppDelegate: UNUserNotificationCenterDelegate {
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        let identifier = response.actionIdentifier
        let userInfo = response.notification.request.content.userInfo

        // when the app has been activated by the user selecting an action from a remote notification
        print("identifier: \(identifier), userInfo: \(userInfo)")

        if let notification = Guardian.notification(from: userInfo),
            let enrollment = AppDelegate.state
        {
            if UNNotificationDefaultActionIdentifier == identifier { // App opened from notification
                show(notification: notification)
                completionHandler()
            } else { // Guardian allow/reject action
                Guardian
                    .authentication(forDomain: AppDelegate.guardianDomain, device: enrollment)
                    .handleAction(withIdentifier: identifier, notification: notification)
                    .start { _ in completionHandler() }
            }
        } else { // Nothing we can handle, just not known notification
            completionHandler()
        }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        let userInfo = notification.request.content.userInfo
        print(userInfo)
        if let notification = Guardian.notification(from: userInfo) {
            show(notification: notification)
        }
        completionHandler([]) //Avoid displaying iOS UI when app in foreground
    }

    private func show(notification: Guardian.Notification) {
        print(notification)

        let notificationController = rootController?.storyboard?.instantiateViewController(withIdentifier: "NotificationView") as! NotificationController
        notificationController.notification = notification
        rootController?.present(notificationController, animated: true, completion: nil)
    }
}
