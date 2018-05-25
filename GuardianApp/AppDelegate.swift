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

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    static let guardianDomain = "guardian-demo.guardian.auth0.com"
    static var enrollment: Enrollment? = nil
    static var pushToken: String? = nil

    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]?) -> Bool {
        // Override point for customization after application launch.

        // Set up push notifications
        let category = Guardian.categoryForNotification(withAcceptTitle: NSLocalizedString("Allow", comment: "Accept Guardian authentication request"),
                                                        rejectTitle: NSLocalizedString("Deny", comment: "Reject Guardian authentication request"))
        let notificationTypes: UIUserNotificationType = [.badge, .sound]
        let pushNotificationSettings = UIUserNotificationSettings(types: notificationTypes, categories: [category])
        application.registerUserNotificationSettings(pushNotificationSettings)
        application.registerForRemoteNotifications()

        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        // when the registration for push notification succeeds
        AppDelegate.pushToken = deviceToken.reduce(String(), {$0 + String(format: "%02X", $1)})
        print("DEVICE TOKEN = \(AppDelegate.pushToken)")
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        // when there's an error and the registration for push notifications failed
        print(error)
    }

    func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any]) {
        // when the app is open and we receive a push notification
        print(userInfo)

        if let notification = Guardian.notification(from: userInfo) {
            print(notification)
            
            let notificationController = rootController?.storyboard?.instantiateViewController(withIdentifier: "NotificationView") as! NotificationController
            notificationController.notification = notification
            rootController?.present(notificationController, animated: true, completion: nil)
        }
    }

    func application(_ application: UIApplication, handleActionWithIdentifier identifier: String?, forRemoteNotification userInfo: [AnyHashable : Any], withResponseInfo responseInfo: [AnyHashable : Any], completionHandler: @escaping () -> Void) {
        // when the app has been activated by the user selecting an action from a remote notification
        print("identifier: \(identifier), userInfo: \(userInfo)")

        if let notification = Guardian.notification(from: userInfo),
            let enrollment = AppDelegate.enrollment,
            let identifier = identifier
        {
            Guardian
                .authentication(forDomain: AppDelegate.guardianDomain, andEnrollment: enrollment)
                .handleAction(withIdentifier: identifier, notification: notification)
                .start { _ in
                    completionHandler()
            }
        } else {
            completionHandler()
        }
    }

    func applicationWillResignActive(_ application: UIApplication) {
        // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
        // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
        // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
    }

    func applicationWillEnterForeground(_ application: UIApplication) {
        // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
    }

    func applicationWillTerminate(_ application: UIApplication) {
        // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
    }

    var rootController: UIViewController? {
        return self.window?.rootViewController
    }
}

