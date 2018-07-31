// EnrolledDevice.swift
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

/**
 A Guardian enrolled device
 
 - seealso: Guardian.enroll
 */
public struct EnrolledDevice: AuthenticationDevice {

    /**
     The enrolled device id from Guardian
     */
    public let id: String

    /**
     The id of the user associated to this device
     */
    public let userId: String

    /**
     The token used to authenticate when updating the device data or deleting 
     it
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
     request for the associated user.
     */
    public let signingKey: SigningKey

    /**
     The TOTP parameters associated to the device

     - important: Might be nil if TOTP mode is disabled
     */
    public let totp: OTPParameters?

    /**
     The identifier of the physical device, for debug/tracking purposes
     */
    public var localIdentifier: String {
        return EnrolledDevice.vendorIdentifier
    }

    /**
     The name to display whenever it is necessary to identify this specific 
     device.

     For example when the user has to choose where to send the push 
     notification, or at the admin interface if the user wants to delete
     an enrolled devicefrom there
     */
    public var name: String {
        return EnrolledDevice.deviceName
    }

    /**
     Creates a new `EnrolledDevice` instance.
     
     - parameter id:                the enrollment id
     - parameter deviceToken:       the token used to authenticate when updating
                                    the device data or deleting it
     - parameter notificationToken: the APNs token for this physical device
     - parameter signingKey:        the private key used to sign Guardian AuthN requests
     - parameter totp:              the TOTP parameters for the enrollment or nil if its disabled
     */
    public init(
         id: String,
         userId: String,
         deviceToken: String,
         notificationToken: String,
         signingKey: SigningKey,
         totp: OTPParameters? = nil
        ) {
        self.id = id
        self.userId = userId
        self.deviceToken = deviceToken
        self.notificationToken = notificationToken
        self.signingKey = signingKey
        self.totp = totp
    }

    static var vendorIdentifier: String {
        return UIDevice.current.identifierForVendor!.uuidString
    }

    static var deviceName: String {
        return UIDevice.current.name
    }
}

/// Parameters for OTP codes
public struct OTPParameters: Codable {
    /// The TOTP secret, Base32 encoded
    public let base32Secret: String
    /// The TOTP algorithm
    public let algorithm: HMACAlgorithm
    /// The TOTP digits, i.e. the code length. Default is 6 digits
    public let digits: Int
    /// The TOTP period, in seconds. Default is 30 seconds
    public let period: Int

    enum CodingKeys: String, CodingKey {
        case base32Secret = "secret"
        case algorithm
        case digits
        case period
    }

    public init(base32Secret: String, algorithm: HMACAlgorithm? = nil, digits: Int? = nil, period: Int? = nil) {
        self.base32Secret = base32Secret
        self.algorithm = algorithm ?? .sha1
        self.digits = digits ?? 6
        self.period = period ?? 30
    }

}
