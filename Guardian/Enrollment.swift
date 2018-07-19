// Enrollment.swift
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
 A Guardian Enrollment
 
 - seealso: Guardian.enroll
 */
public class Enrollment: NSObject {

    /**
     The enrollment id
     */
    public let id: String

    /**
     The id of this enrollment's user
     */
    public let userId: String

    /**
     The token used to authenticate when updating the device data or deleting 
     the enrollment
     */
    public let deviceToken: String

    /**
     The APNs token for this physical device, required to check against the 
     current token and update the server in case it's not the same.

     - important: Needs to be kept up-to-date on the server for the push 
                  notifications to work.
     */
    public let notificationToken: String

    /**
     The private key used to sign the requests to allow/reject an authentication
     request.
     */
    public let signingKey: RSAPrivateKey

    /**
     The TOTP secret, Base32 encoded

     - important: Might be nil if TOTP mode is disabled
     */
    public let base32Secret: String?

    /**
     The TOTP algorithm
     */
    public let algorithm: String

    /**
     The TOTP digits, i.e. the code length
     */
    public let digits: Int

    /**
     The TOTP period, in seconds
     */
    public let period: Int

    /**
     The identifier of the physical device, for debug/tracking purposes
     */
    public var deviceIdentifier: String {
        return Enrollment.defaultDeviceIdentifier
    }

    /**
     The name to display whenever it is necessary to identify this specific 
     enrollment. 

     For example when the user has to choose where to send the push 
     notification, or at the admin interface if the user wants to delete an 
     enrollment from there
     */
    public var deviceName: String {
        return Enrollment.defaultDeviceName
    }

    /**
     Creates a new `Enrollment` instance.
     
     - parameter id:                the enrollment id
     - parameter deviceToken:       the token used to authenticate when updating
                                    the device data or deleting the enrollment
     - parameter notificationToken: the APNs token for this physical device
     - parameter signingKey:        the private key used to sign the requests
     - parameter base32Secret:      the TOTP secret, Base32 encoded
     - parameter algorithm:         the TOTP algorithm
     - parameter digits:            the TOTP digits, i.e. the code length
     - parameter period:            the TOTP period, in seconds
     */
    public init(
         id: String,
         userId: String,
         deviceToken: String,
         notificationToken: String,
         signingKey: RSAPrivateKey,
         base32Secret: String?,
         algorithm: String? = nil,
         digits: Int? = nil,
         period: Int? = nil
        ) {
        self.id = id
        self.userId = userId
        self.deviceToken = deviceToken
        self.notificationToken = notificationToken
        self.signingKey = signingKey
        self.base32Secret = base32Secret
        self.algorithm = algorithm ?? "sha1"
        self.digits = digits ?? 6
        self.period = period ?? 30
    }
}

extension Enrollment {

    class var defaultDeviceName: String {
        return UIDevice.current.name
    }

    class var defaultDeviceIdentifier: String {
        return UIDevice.current.identifierForVendor!.uuidString
    }
}
