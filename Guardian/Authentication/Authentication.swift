// Authentication.swift
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
 An `Authentication` lets you allow or reject a `Notification`
 
 ```
 let enrollment: Enrollment = // the object you obtained when enrolling
 let authenticator = Guardian
    .authentication(forDomain: "tenant.guardian.auth0.com", andEnrollment: enrollment)
 ```
 */
public protocol Authentication {

    /**
     Allows/verifies the authentication request

     ```
     let enrollment: Enrollment = // the object you obtained when enrolling
     let notification: Notification = // the notification received
     Guardian
        .authentication(forDomain: "tenant.guardian.auth0.com", andEnrollment: enrollment)
        .allow(notification: notification)
        .start { result in
            switch result {
            case .success(_):
                // auth request allowed successfuly
            case .sailure(let cause):
                // failed to allow auth request
            }
     }
     ```

     - parameter notification: the notification that contains the authentication
                               request that should be allowed.
     
     - returns: a request to execute
     */
    func allow(notification: Notification) -> Request<Void>

    /**
     Reject/denies the authentication request
     
     ```
     let enrollment: Enrollment = // the object you obtained when enrolling
     let notification: Notification = // the notification received
     Guardian
        .authentication(forDomain: "tenant.guardian.auth0.com", andEnrollment: enrollment)
        .reject(notification: notification, withReason: "mistake")
        .start { result in
            switch result {
            case .success(_):
                // auth request rejected successfuly
            case .failure(let cause):
                // failed to reject auth request
            }
     }
     ```

     - parameter notification: the notification that contains the authentication
                               request that should be allowed.
     - parameter withReason:   an optional string that identifies the reason why
                               this authentication request is being rejected.

     - returns: a request to execute
     */
    func reject(notification: Notification, withReason reason: String?) -> Request<Void>

    /**
     Handles the Guardian remote notification action matching the supplied 
     identifier.

     You could use this method in your AppDelegate's `application(:handleActionWithIdentifier:forRemoteNotification:withResponseInfo:completionHandler)`
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
     */
    func handleAction(withIdentifier identifier: String, notification: Notification) -> Request<Void>
}

public extension Authentication {
    public func reject(notification: Notification, withReason reason: String? = nil) -> Request<Void> {
        return self.reject(notification: notification, withReason: reason)
    }
}

struct RSAAuthentication: Authentication {

    private static let challengeResponseExpiresInSecs = 30

    let api: API
    let device: AuthenticationDevice

    func allow(notification: Notification) -> Request<Void> {
        return resolve(transaction: notification.transactionToken,
                       withChallenge: notification.challenge,
                       accepted: true)
    }

    func reject(notification: Notification, withReason reason: String?) -> Request<Void> {
        return resolve(transaction: notification.transactionToken,
                       withChallenge: notification.challenge,
                       accepted: false,
                       reason: reason)
    }

    func resolve(transaction transactionToken: String, withChallenge challenge: String, accepted: Bool, reason: String? = nil) -> Request<Void> {
        do {
            let currentTime = Int(Date().timeIntervalSince1970)
            var jwtPayload: [String: Any] = [
                "iat": currentTime,
                "exp": currentTime + RSAAuthentication.challengeResponseExpiresInSecs,
                "aud": self.api.baseUrl.appendingPathComponent("api/resolve-transaction").absoluteString,
                "iss": self.device.localIdentifier,
                "sub": challenge,
                "auth0_guardian_method": "push",
                "auth0_guardian_accepted": accepted
            ]
            if let reason = reason {
                jwtPayload["auth0_guardian_reason"] = reason
            }
            let jwt = try JWT.encode(claims: jwtPayload, signingKey: self.device.signingKey.secKey)
            return self.api.resolve(transaction: transactionToken, withChallengeResponse: jwt)
        } catch(let error) {
            return FailedRequest(error: error)
        }
    }

    func handleAction(withIdentifier identifier: String, notification: Notification) -> Request<Void> {
        let category = AuthenticationCategory.default
        if category.allow.identifier == identifier {
            return allow(notification: notification)
        }
        if category.reject.identifier == identifier {
            return reject(notification: notification)
        }
        return FailedRequest(error: GuardianError.invalidNotificationActionIdentifier)
    }
}
