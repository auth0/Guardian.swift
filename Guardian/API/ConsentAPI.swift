// ConsentAPI.swift
//
// Copyright (c) 2024 Auth0 (http://auth0.com)
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
 `ConsentAPI` lets you retrieve consent objects from auth0's rich-consents API for authentication flows that require additional consent e.g. Client Initiated Backchannel Authentication (CIBA)
 
 ```
 let consent = Guardian
    .consent(forDomain: "tenant.region.auth0.com")
 ```
 */
public protocol ConsentAPI {
    /**
     ```
     let notification: Notification = // the notification received
     let consentId = notification.transactionLinkingId
     
     Guardian
        .consent(forDomain: "tenant.region.auth0.com")
     .fetch(consentId: consentId, notificationToken: notification.transactionToken, signingKey: enrollment.signingKey)
     .start { result in
          switch result {
          case .success(let payload):
              // present consent object to user to accept/deny
          case .failure(let cause):
              // failed to retrieve consent
          }
     }
     ```
     
     - parameter consentId: the id of the consent object to fetch, this is obtained from the
                            transaction linking id of the ncoming push notification where relevant
     - parameter transactionToken: the access token obtained from the incoming push notification
     - parameter signingKey: the private key used to sign Guardian AuthN requests
                                    
     - returns: a request to execute
     */
    func fetch(consentId: String, transactionToken: String, signingKey: SigningKey) -> Request<NoContent, Consent>
}
