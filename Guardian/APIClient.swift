// APIClient.swift
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

public struct APIClient: API {

    let baseUrl: NSURL
    let session: NSURLSession
    
    public init(baseUrl: NSURL, session: NSURLSession) {
        self.baseUrl = baseUrl
        self.session = session
    }
    
    public func enrollment(forTransactionId transactionId: String) -> Request<[String: String]> {
        let url = baseUrl.URLByAppendingPathComponent("api/enrollment-info")!
        let payload = ["enrollment_tx_id": transactionId]
        return Request(session: session, method: "POST", url: url, payload: payload)
    }
    
    public func allow(transaction transactionToken: String, withCode otpCode: String) -> Request<Void> {
        let url = baseUrl.URLByAppendingPathComponent("api/verify-otp")!
        let payload = [
            "type": "push_notification",
            "code": otpCode
        ]
        return Request(session: session, method: "POST", url: url, payload: payload, headers: ["Authorization": "Bearer \(transactionToken)"])
    }
    
    public func reject(transaction transactionToken: String, withCode otpCode: String, reason: String? = nil) -> Request<Void> {
        let url = baseUrl.URLByAppendingPathComponent("api/reject-login")!
        var payload = [
            "code": otpCode
        ]
        if let reason = reason {
            payload["reason"] = reason
        }
        return Request(session: session, method: "POST", url: url, payload: payload, headers: ["Authorization": "Bearer \(transactionToken)"])
    }
    
    public func device(forEnrollmentId id: String, token: String) -> DeviceAPI {
        return DeviceAPIClient(baseUrl: baseUrl, session: session, id: id, token: token)
    }
}
