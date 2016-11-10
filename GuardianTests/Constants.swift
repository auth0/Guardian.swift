// Constants.swift
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

let Domain = "tenant.guardian.auth0.com"
let Timeout: TimeInterval = 2

let ValidURL = URL(string: "https://\(Domain)/")!
let ValidTransactionId = UUID().uuidString
let ValidEnrollmentId = UUID().uuidString
let ValidEnrollmentToken = UUID().uuidString
let ValidNotificationToken = UUID().uuidString
let ValidIssuer = "aValidIssuer"
let ValidUser = "aValidUser"
let ValidBase32Secret = "aValidBase32Secret"
let InvalidBase32Secret = "anInvalidBase32Secret!?"
let ValidAlgorithm = "SHA1"
let ValidDigits = 7
let ValidPeriod = 29
let ValidTransactionToken = "aValidTransactionToken"
let ValidOTPCode = "aValidOTPCode"
let ValidOTPCodeWithRejectReason = "aValidOTPCodeWithRejectReason"
let RejectReason = "aRejectReason"

let ValidDeviceIdentifier = "aValidDeviceIdentifier"
let ValidDeviceName = "aValidDeviceName"
let ValidNotificationService = "APNS"
let DeviceAccountToken = UUID().uuidString

let RSAPublicKeyTag = UUID().uuidString
let RSAPrivateKeyTag = UUID().uuidString
let RSAKeySize = 2048

let (ValidRSAPublicKey, ValidRSAPrivateKey) = generateKeyPair(publicTag: RSAPublicKeyTag, privateTag: RSAPrivateKeyTag, keyType: kSecAttrKeyTypeRSA, keySize: RSAKeySize)!
let NonRSAPublicKey = generateKeyPair(publicTag: RSAPublicKeyTag + "-invalid", privateTag: RSAPrivateKeyTag + "-invalid", keyType: kSecAttrKeyTypeEC, keySize: 256)!.publicKey
