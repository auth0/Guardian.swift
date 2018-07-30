// Request.swift
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

let errorBuilder = { (response: HTTPURLResponse, data: Data?) -> Swift.Error? in
    let decoder = JSONDecoder()
    guard let data = data else { return nil }
    return try? decoder.decode(GuardianError.self, from: data)
}

public struct Request<T: Encodable, E: Decodable>: Operation {
    let request: NetworkOperation<T, E>

    static func new(method: HTTPMethod, url: URL, headers: [String: String] = [:], body: T? = nil) -> Request<T, E>{
        do {
            let request: NetworkOperation<T, E> = try NetworkOperation(method: method, url: url, headers: headers, body: body).mapError(transform: errorBuilder)
            return Request(request: request)
        } catch let error {
            return Request(method: method, url: url, error: error)
        }
    }

    private init(request: NetworkOperation<T, E>) {
        self.request = request
    }

    init(method: HTTPMethod, url: URL, error: Swift.Error) {
        let request: NetworkOperation<T, E> = NetworkOperation(method: method, url: url, error: error)
        self.init(request: request)
    }

    public func start(callback: @escaping (Result<E>) -> ()) {
        self.request.start(callback: callback)
    }

    public func on(request: OnRequestEvent? = nil, response: OnResponseEvent? = nil) -> Request<T, E> {
        let request = self.request.on(request: request, response: response)
        return Request(request: request)
    }

    public func mapError(transform: @escaping (HTTPURLResponse, Data?) -> Swift.Error?) -> Request<T, E> {
        let request = self.request.mapError { (response, data) -> Swift.Error? in
            return transform(response, data) ?? errorBuilder(response, data)
        }
        return Request(request: request)
    }

    public func withURLSession(_ session: URLSession) -> Request<T, E> {
        let request = self.request.withURLSession(session)
        return Request(request: request)
    }

    public var description: String { return self.request.description }
    public var debugDescription: String { return self.request.debugDescription }
}
