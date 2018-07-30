// Events.swift
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

/// Hook that will be called before request is sent
public typealias OnRequestEvent = (RequestEvent) -> ()
/// Hook that will be called when a response is received (any status code) along with data (if any)
public typealias OnResponseEvent = (ResponseEvent) -> ()

public protocol RequestEvent {
    var request: URLRequest { get }
}

public protocol ResponseEvent {
    var response: HTTPURLResponse { get }
    var data: Data? { get }
    var rateLimit: RateLimit? { get }
}

public struct RateLimit {
    public let limit: Int
    public let remaining: Int
    public let resetAt: Date

    init?(response: HTTPURLResponse) {
        guard let limitValue = response.value(forHeader: "X-RateLimit-Limit"),
            let limit = Int(limitValue),
            let remainingValue = response.value(forHeader: "X-RateLimit-Remaining"),
            let remaining = Int(remainingValue),
            let resetValue = response.value(forHeader: "X-RateLimit-Reset"),
            let resetSeconds = TimeInterval(resetValue)
            else { return nil }
        let resetAt = Date(timeIntervalSince1970: resetSeconds)
        self.limit = limit
        self.remaining = remaining
        self.resetAt = resetAt
    }
}

struct NetworkObserver {
    let request: OnRequestEvent?
    let response: OnResponseEvent?

    init(request: OnRequestEvent? = nil, response: OnResponseEvent? = nil) {
        self.request = request
        self.response = response
    }
}
