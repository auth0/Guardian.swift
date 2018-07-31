// DeviceAPIClient.swift
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

struct DeviceAPIClient: DeviceAPI {
    let url: URL
    let token: String
    
    init(baseUrl: URL, id: String, token: String) {
        self.url = baseUrl.appendingPathComponent("api/device-accounts/\(id)")
        self.token = token
    }
    
    func delete() -> Request<NoContent, NoContent> {
        return Request.new(method: .delete, url: url, headers: ["Authorization": "Bearer \(token)"])
    }
    
    func update(localIdentifier identifier: String? = nil, name: String? = nil, notificationToken: String? = nil) -> Request<UpdatedDevice, UpdatedDevice> {
        let credentials: PushCredentials?
        if let notificationToken = notificationToken {
            credentials = PushCredentials(token: notificationToken)
        } else {
            credentials = nil
        }
        let update = UpdatedDevice(identifier: identifier, name: name, pushCredentials: credentials)
        return Request.new(method: .patch, url: url, headers: ["Authorization": "Bearer \(token)"], body: update)
    }
}
