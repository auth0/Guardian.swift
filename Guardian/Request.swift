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

/// Definition of function to log a string
public typealias Logger = (String) -> ()

/// Default logger using Swift print function
let defaultLogger: Logger = { (line: String) in print(line) }

/**
 An asynchronous HTTP request
 */
public class Request<T>: Requestable, CustomDebugStringConvertible {

    let session: URLSession
    let method: String
    let url: URL
    let payload: [String: Any]?
    let headers: [String: String]
    var logger: Logger? = nil
    
    init(session: URLSession, method: String, url: URL, payload: [String: Any]? = nil, headers: [String: String]? = nil) {
        self.session = session
        self.method = method
        self.url = url
        self.payload = payload
        let bundle = Bundle(for: _ObjectiveGuardian.classForCoder())
        var headers = headers ?? [:]
        if let version = bundle.infoDictionary?["CFBundleShortVersionString"] as? String,
            let clientInfo = try? JSONSerialization.data(withJSONObject: [
                "name": "Guardian.swift",
                "version": version
                ])
        {
            headers["Auth0-Client"] = clientInfo.base64URLEncodedString()
        }

        if payload != nil {
            headers["Content-Type"] = "application/json"
        }
        self.headers = headers
    }

    public var debugDescription: String {
        var description = "\(self.method) \(self.url)\n"
        self.headers.forEach { description.append("\($0): \($1)") }
        description.append("\n")
        if let payload = self.payload,
            let body = try? JSONSerialization.data(withJSONObject: payload, options: .prettyPrinted),
            let json = String(data: body, encoding: .utf8) {
            description.append(json.replacingOccurrences(of: "\\n", with: "\n"))
        }
        return description
    }

    /// Makes the operation logs the request payload. By default it will log to console
    ///
    /// - Parameter logger: function that will log the information provided
    /// - Returns: the request itself for chaining
    public func log(into logger: @escaping Logger = defaultLogger) -> Request<T> {
        self.logger = logger
        return self
    }

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is 
                           received
     */
    public func start(callback: @escaping (Result<T>) -> ()) {
        let request = NSMutableURLRequest(url: url)
        request.httpMethod = self.method
        self.headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }

        if let payload = payload {
            guard let body = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
                callback(.failure(cause: GuardianError.invalidPayload))
                return
            }
            request.httpBody = body
        }

        self.logger?(self.debugDescription)

        let task = self.session.dataTask(with: request as URLRequest) { data, response, error in
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
            if let payload: T = json(data) {
                callback(.success(payload: payload))
            } else if T.self is Void.Type {
                callback(.success(payload: Void() as! T))
            } else {
                callback(.failure(cause: GuardianError.invalidResponse(withStatus: httpResponse.statusCode)))
            }
        }
        task.resume()
    }
}

func json<T>(_ data: Data?) -> T? {
    guard let data = data else { return nil }
    let object = try? JSONSerialization.jsonObject(with: data, options: [])
    return object as? T
}
