// NetworkOperation.swift
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

public struct NetworkOperation<T: Decodable> {

    let request: URLRequest

    init(method: HTTPMethod, url: URL, headers: [String: String] = [:], body: Encodable? = nil) throws {
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue.uppercased()
        headers.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }

        self.request = request
    }

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is received
     */
    public func start(callback: @escaping (Result<T>) -> ()) {
        
    }

}

enum HTTPMethod: String {
    case get
    case post
    case patch
    case delete
}
