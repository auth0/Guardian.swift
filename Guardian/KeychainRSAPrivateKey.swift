// KeychainRSAPrivateKey.swift
//
// Copyright (c) 2018 Auth0 (http://auth0.com)
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

/// iOS keychain backed key
public struct KeychainRSAPrivateKey: SigningKey {

    public let tag: String
    public let secKey: SecKey

    /**
     Creates a new instance looking for a Keychain backed Private Key
     - parameter tag: identifier that will be used to locate the key
     - throws: `GuardianError` if the key is not found
    */
    public init(tag: String) throws {
        self.init(tag: tag, secKey: try retrieveKey(of: tag))
    }

    init(tag: String, secKey: SecKey) {
        self.tag = tag
        self.secKey = secKey
    }

    /// Available types of key accessibility in the keychain
    public enum Accessibility {
        /// key available after one device unlock after restart (allows backups)
        case afterFirstUnlock
        /// key available after one device unlock after restart (does not allows backups)
        case afterFirstUnlockThisDeviceOnly
        /// key only available if there is a passcode, otherwise it will be removed
        case whenPasscodeIsSet

        var kSecAttr: CFString {
            switch self {
            case .afterFirstUnlock:
                return kSecAttrAccessibleAfterFirstUnlock
            case .afterFirstUnlockThisDeviceOnly:
                return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            case .whenPasscodeIsSet:
                return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            }
        }
    }
}
