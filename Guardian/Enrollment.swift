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
    let apnsToken: String
    
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
         apnsToken: String,
         issuer: String,
         user: String,
         base32Secret: String,
         algorithm: String,
         digits: Int,
         period: Int) {
        self.baseURL = baseURL
        self.id = id
        self.deviceToken = deviceToken
        self.apnsToken = apnsToken
        self.issuer = issuer
        self.user = user
        self.base32Secret = base32Secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
    }
}

struct EnrollmentData {
    
    let enrollmentTxId: String
    let id: String
    
    let baseURL: NSURL
    let issuer: String
    let user: String
    
    let period: Int
    let digits: Int
    let algorithm: String
    let base32Secret: String
    
    init?(uriString: String) {
        guard let components = NSURLComponents(string: uriString), let otp = components.host?.lowercaseString
            where components.scheme == "otpauth" && otp == "totp" else {
                return nil
        }
        guard let path = components.path where !path.isEmpty, let parameters = components.queryItems?.asDictionary() else {
            return nil
        }
        let label = path.substringFromIndex(path.startIndex.advancedBy(1))
        let issuer = parameters["issuer"]
        var user: String?
        if label.containsString(":") {
            var labelParts = label.componentsSeparatedByString(":")
            guard issuer == labelParts.removeFirst() else {
                return nil
            }
            user = labelParts.first
        }
        guard issuer != nil && user != nil,
            let identifier = parameters["id"],
            let secret = parameters["secret"],
            let enrollmentTxId = parameters["enrollment_tx_id"],
            let urlString = parameters["base_url"],
            let url = NSURL(string: urlString) else {
                return nil
        }
        
        self.user = user!
        self.issuer = issuer!
        self.id = identifier
        self.enrollmentTxId = enrollmentTxId
        self.baseURL = url
        self.base32Secret = secret
        self.algorithm = parameters["algorithm"] ?? "sha1"
        self.digits = Int(parameters["digits"]) ?? 6
        self.period = Int(parameters["period"]) ?? 30
    }
}

private extension Int {
    
    init?(_ value: String?) {
        guard value != nil else {
            return nil
        }
        self.init(value!)
    }
}

private extension Array where Element: NSURLQueryItem {
    
    func asDictionary() -> [String: String] {
        return self.reduce([:], combine: { (dict, item) in
            var values = dict
            if let value = item.value {
                values[item.name] = value
            }
            return values
        })
    }
}