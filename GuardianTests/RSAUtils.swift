// RSAUtils.swift
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

func generateKeyPair(publicTag: String, privateTag: String, keyType: CFString, keySize: Int) -> (publicKey: SecKey, privateKey: SecKey)? {
    let privateAttributes = [String(kSecAttrIsPermanent): true,
                             String(kSecAttrApplicationTag): privateTag] as [String : Any]
    let publicAttributes = [String(kSecAttrIsPermanent): true,
                            String(kSecAttrApplicationTag): publicTag] as [String : Any]

    let pairAttributes = [String(kSecAttrKeyType): keyType,
                          String(kSecAttrKeySizeInBits): keySize,
                          String(kSecPublicKeyAttrs): publicAttributes,
                          String(kSecPrivateKeyAttrs): privateAttributes] as [String : Any]

    var publicRef: SecKey?
    var privateRef: SecKey?
    switch SecKeyGeneratePair(pairAttributes as CFDictionary, &publicRef, &privateRef) {
    case noErr:
        if let publicKey = publicRef, let privateKey = privateRef {
            return (publicKey, privateKey)
        }

        return nil
    default:
        return nil
    }
}
