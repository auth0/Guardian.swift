// API.swift
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
 Low level API client for Guardian MFA server
 
 Use this API client to manually create enrollments, allow/reject authentication
 requests, and manage an enrollment's device data

 ```
 let api = Guardian.api(forDomain: "tenant.guardian.auth0.com")
 ```

 */
public protocol API {

    /**
     Request to obtain information about an enrollment
     The transaction id can be obtained from a Guardian QR code
     
     ```
     Guardian
        .api(forDomain: "tenant.guardian.auth0.com")
        .enrollment(forTransactionId: "myEnrollmentTransactionId")
        .start { result in
            switch result {
            case .Success(let response):
                // we have the data
                print(response)
            case .Failure(let cause):
                // something failed
                print(cause)
            }
     }
     ```
     
     - parameter forTransactionId: the enrollment transaction id
     
     - returns: a Request ready to execute
     */
    func enrollment(forTransactionId transactionId: String) -> Request<[String: String]>

    /**
     Request to allow a Guardian authentication request
     
     ```
     Guardian
        .api(forDomain: "tenant.guardian.auth0.com")
        .allow(transaction: notification.transactionToken,
               withCode: "someOTPCode")
        .start { result in
            switch result {
            case .Success(let response):
                // auth request successfuly allowed
            case .Failure(let cause):
                // something failed
                print(cause)
            }
     }
     ```

     - parameter transaction: the Guardian authentication transaction
     - parameter withCode:    the code to validate the second factor

     - returns: a Request ready to execute
     */
    func allow(transaction transactionToken: String, withCode otpCode: String) -> Request<Void>

    /**
     Request to reject a Guardian authentication request

     ```
     Guardian
        .api(forDomain: "tenant.guardian.auth0.com")
        .reject(transaction: notification.transactionToken, 
                withCode: "someOTPCode", 
                reason: "hack")
        .start { result in
            switch result {
            case .Success(let response):
                // auth request successfuly rejected
            case .Failure(let cause):
                // something failed
                print(cause)
            }
     }
     ```

     - parameter transaction: the Guardian authentication transaction
     - parameter withCode:    the code to validate the second factor
     - parameter reason:      an optional reason of rejection (example: "hack")

     - returns: a Request ready to execute
     */
    func reject(transaction transactionToken: String, withCode otpCode: String, reason: String?) -> Request<Void>

    /**
     Returns a DeviceAPI to manage the device data about an enrollment.
     This allows to change the name of the device, to update the push 
     notification token or to delete the device, unenrolling/disabling this 
     device as a second factor.
     
     ```
     Guardian
        .api(forDomain: "tenant.guardian.auth0.com")
        .device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
        .create() // or update/delete
     ```

     - parameter forEnrollmentId: the enrollment id
     - parameter token:           the token that will be used to authenticate
     
     - returns: a DeviceAPI instance
     */
    func device(forEnrollmentId id: String, token: String) -> DeviceAPI
}
