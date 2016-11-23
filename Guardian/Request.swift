// Request.swift
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

/**
 An asynchronous HTTP request
 */
public struct Request<T>: Requestable {

    let session: URLSession
    let method: String
    let url: URL
    let payload: [String: Any]?
    let headers: [String: String]?
    
    init(session: URLSession, method: String, url: URL, payload: [String: Any]? = nil, headers: [String: String]? = nil) {
        self.session = session
        self.method = method
        self.url = url
        self.payload = payload
        self.headers = headers
    }

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is 
                           received
     */
    public func start(callback: @escaping (Result<T>) -> ()) {
        let request = NSMutableURLRequest(url: url)
        request.httpMethod = method
        
        if let payload = payload {
            guard let body = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
                callback(.failure(cause: GuardianError.invalidPayload))
                return
            }
            request.httpBody = body
        }

        let bundle = Bundle(for: _ObjectiveGuardian.classForCoder())
        if let version = bundle.infoDictionary?["CFBundleShortVersionString"] as? String,
            let clientInfo = try? JSONSerialization.data(withJSONObject: [
                "name": "Guardian.swift",
                "version": version
                ])
        {
            request.setValue(clientInfo.base64URLEncodedString(), forHTTPHeaderField: "Auth0-Client")
        }

        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        headers?.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        
        let task = session.dataTask(with: request as URLRequest) { data, response, error in
            if let error = error { return callback(.failure(cause: error)) }
            guard let httpResponse = response as? HTTPURLResponse else {
                return callback(.failure(cause: GuardianError.invalidResponse))
            }
            guard (200..<300).contains(httpResponse.statusCode) else {
                guard let info: [String: Any] = json(data) else {
                    return callback(.failure(cause: GuardianError.invalidResponse(withStatus: httpResponse.statusCode)))
                }
                return callback(.failure(cause: GuardianError(info: info, statusCode: httpResponse.statusCode)))
            }
            callback(.success(payload: json(data)))
        }
        task.resume()
    }
}

func json<T>(_ data: Data?) -> T? {
    guard let data = data else { return nil }
    let object = try? JSONSerialization.jsonObject(with: data, options: [])
    return object as? T
}
