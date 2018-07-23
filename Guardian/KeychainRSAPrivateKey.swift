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

public struct KeychainRSAPrivateKey: SigningKey {
    public let tag: String

    public init(tag: String) {
        self.tag = tag
    }
    
    /**
     Returns the `SecKey` instance

     - important: This method might return nil if a key with this tag is not
     present in the keychain or if the type of the key is not
     appropriate.
     */
    public var secKey: SecKey? {
        let query: [String: Any] = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : self.tag,
            String(kSecReturnRef)          : true
        ]
        var out: CFTypeRef?
        let result = SecItemCopyMatching(query as CFDictionary, &out)
        guard errSecSuccess == result else {
            return nil
        }

        return (out as! SecKey)
    }

    public enum Accessibility {
        case afterFirstUnlock
        case afterFirstUnlockThisDeviceOnly
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
