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
    func allow(notification: Notification) -> Request<Transaction, NoContent>

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
    func reject(notification: Notification, withReason reason: String?) -> Request<Transaction, NoContent>

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
    func handleAction(withIdentifier identifier: String, notification: Notification) -> Request<Transaction, NoContent>
}

public extension Authentication {
    public func reject(notification: Notification, withReason reason: String? = nil) -> Request<Transaction, NoContent> {
        return self.reject(notification: notification, withReason: reason)
    }
}

struct RSAAuthentication: Authentication {

    private static let reponseExpiration: TimeInterval = 30

    let api: API
    let device: AuthenticationDevice

    func allow(notification: Notification) -> Request<Transaction, NoContent> {
        return resolve(transaction: notification.transactionToken,
                       withChallenge: notification.challenge,
                       accepted: true)
    }

    func reject(notification: Notification, withReason reason: String?) -> Request<Transaction, NoContent> {
        return resolve(transaction: notification.transactionToken,
                       withChallenge: notification.challenge,
                       accepted: false,
                       reason: reason)
    }

    func resolve(transaction transactionToken: String, withChallenge challenge: String, accepted: Bool, reason: String? = nil) -> Request<Transaction, NoContent> {
        let path = self.api.baseUrl.appendingPathComponent("api/resolve-transaction")
        let currentTime = Date()
        let claims = GuardianClaimSet(
            subject: challenge,
            issuer: self.device.localIdentifier,
            audience: path.absoluteString,
            expireAt: currentTime.addingTimeInterval(RSAAuthentication.reponseExpiration),
            issuedAt: currentTime,
            status: accepted,
            reason: reason
        )
        let jwt: JWT<GuardianClaimSet>
        do {
            jwt = try JWT(claimSet: claims, key: self.device.signingKey.secKey)
        } catch(let error) {
            return Request(method: .post, url: path, error: GuardianError(code: .cannotSignTransactionChallenge, cause: error))
        }
        return self.api.resolve(transaction: transactionToken, withChallengeResponse: jwt.string)
    }

    func handleAction(withIdentifier identifier: String, notification: Notification) -> Request<Transaction, NoContent> {
        let category = AuthenticationCategory.default
        if category.allow.identifier == identifier {
            return allow(notification: notification)
        }
        if category.reject.identifier == identifier {
            return reject(notification: notification)
        }
        let path = self.api.baseUrl.appendingPathComponent("api/resolve-transaction")
        return Request(method: .post, url: path, error: GuardianError(code: .invalidNotificationActionIdentifier))
    }
}
