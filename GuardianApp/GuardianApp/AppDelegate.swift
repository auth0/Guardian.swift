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
@preconcurrency import Guardian
import UserNotifications

@main
class AppDelegate: UIResponder, UIApplicationDelegate {

    static var pushToken: String?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        print("Guardian tenant: \(GuardianService.tenantDomain)")

        // Allow and Deny actions on Guardian login request notifications
        let category = GuardianService.notificationCategory()

        // Request for AuthZ
        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().setNotificationCategories([category])
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { granted, error in
            guard granted else {
                return print("Permission not granted")
            }
            if let error = error {
                return print("failed with error \(error)")
            }

            // Check AuthZ status to trigger remote notification registration
            UNUserNotificationCenter.current().getNotificationSettings { settings in
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
        let token = deviceToken.reduce(String(), { $0 + String(format: "%02X", $1) })
        AppDelegate.pushToken = token
        // Needed to set up push on a test tenant; never log it in release builds.
        #if DEBUG
        print("DEVICE TOKEN = \(token)")
        #endif
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Swift.Error) {
        // when there's an error and the registration for push notifications failed
        print(error)
    }

    var rootController: UIViewController? {
        UIApplication.shared.connectedScenes
            .compactMap { ($0.delegate as? SceneDelegate)?.window }
            .first?
            .rootViewController
    }
}

extension AppDelegate {
    static var state: GuardianState? {
        get {
            GuardianState.load()
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

// UIKit calls the notification center delegate on the main thread.
extension AppDelegate: @preconcurrency UNUserNotificationCenterDelegate {
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let identifier = response.actionIdentifier
        let userInfo = response.notification.request.content.userInfo

        // when the app has been activated by the user selecting an action from a remote notification
        // Don't log userInfo: the Guardian payload carries the transaction token.
        print("Notification action: \(identifier)")

        if let notification = GuardianService.notification(from: userInfo),
            let enrollment = AppDelegate.state {
            if UNNotificationDefaultActionIdentifier == identifier { // App opened from notification
                show(notification: notification)
                completionHandler()
            } else { // Guardian allow/reject action
                GuardianService.handleAction(withIdentifier: identifier, notification: notification, device: enrollment) { _ in
                    completionHandler()
                }
            }
        } else { // Nothing we can handle, just not known notification
            completionHandler()
        }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        let userInfo = notification.request.content.userInfo
        if let notification = GuardianService.notification(from: userInfo) {
            show(notification: notification)
        }
        completionHandler([]) // Avoid displaying iOS UI when app in foreground
    }

    private func show(notification: Guardian.Notification) {
        let storyboard = rootController?.storyboard
        guard let notificationController = storyboard?.instantiateViewController(withIdentifier: "NotificationView") as? NotificationController else {
            return print("NotificationView is missing from Main.storyboard")
        }
        notificationController.notification = notification
        rootController?.present(notificationController, animated: true, completion: nil)
    }
}
