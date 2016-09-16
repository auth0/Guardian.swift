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

public struct Enrollment {
    
    let baseURL: NSURL
    let id: String
    let deviceToken: String
    let notificationToken: String
    
    let issuer: String
    let user: String
    
    let base32Secret: String
    let algorithm: String
    let digits: Int
    let period: Int
    
    var deviceIdentifier: String {
        return UIDevice.currentDevice().identifierForVendor!.UUIDString
    }
    
    var deviceName: String {
        return UIDevice.currentDevice().name
    }
    
    init(baseURL: NSURL,
         id: String,
         deviceToken: String,
         notificationToken: String,
         issuer: String,
         user: String,
         base32Secret: String,
         algorithm: String? = nil,
         digits: Int? = nil,
         period: Int? = nil) {
        self.baseURL = baseURL
        self.id = id
        self.deviceToken = deviceToken
        self.notificationToken = notificationToken
        self.issuer = issuer
        self.user = user
        self.base32Secret = base32Secret
        self.algorithm = algorithm ?? "sha1"
        self.digits = digits ?? 6
        self.period = period ?? 30
    }
}
