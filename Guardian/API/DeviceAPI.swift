// DeviceAPI.swift
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
 Enrollment's device management API client
 
 Use this API client to create, update or delete an enrollment's device

 ```
 let deviceAPI = Guardian
        .api(forDomain: "tenant.guardian.auth0.com")
        .device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
 ```
 */
public protocol DeviceAPI {

    /**
     Request to delete a device, invalidating the corresponding enrollment.

     ```
     Guardian
        .api(forDomain: "tenant.guardian.auth0.com")
        .device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
        .delete()
        .start { result in
            switch result {
            case .success(let response):
                // device/enrollment deleted successfuly
            case .failure(let cause):
                // something failed
                print(cause)
            }
     }
     ```

     - returns: a Request ready to execute
     
     - important: The second factor will be disabled if this was the only 
                  enrollment
     */
    func delete() -> Request<NoContent, NoContent>

    /**
     Request to update the data of the device.
     If any of the parameters is not explicitly set (or `nil`), they will remain
     unchanged.

     ```
     Guardian
        .api(forDomain: "tenant.guardian.auth0.com")
        .device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
        .update(localIdentifier: enrollment.deviceIdentifier
                name: enrollment.deviceName
                notificationToken: enrollment.notificationToken)
        .start { result in
            switch result {
            case .success(let response):
                // device data updated successfuly
            case .failure(let cause):
                // something failed
                print(cause)
            }
     }
     ```

     - parameter localIdentifier:  a unique identifier for this device, usually
                                    the UUID
     - parameter name:              the name to use for this device
     - parameter notificationToken: the APNS token used to send push 
                                    notifications to this device

     - returns: a Request ready to execute
     */
    func update(localIdentifier identifier: String?, name: String?, notificationToken: String?) -> Request<UpdatedDevice, UpdatedDevice>
}
