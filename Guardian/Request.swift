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

public struct Request<T> : Requestable {

    let session: NSURLSession
    let method: String
    let url: NSURL
    let payload: [String: AnyObject]?
    let headers: [String: String]?
    
    init(session: NSURLSession, method: String, url: NSURL, payload: [String: AnyObject]? = nil, headers: [String: String]? = nil) {
        self.session = session
        self.method = method
        self.url = url
        self.payload = payload
        self.headers = headers
    }

    public func start(callback: (Result<T>) -> ()) {
        let request = NSMutableURLRequest(URL: url)
        request.HTTPMethod = method
        
        if let payload = payload {
            guard let body = try? NSJSONSerialization.dataWithJSONObject(payload, options: []) else {
                callback(.Failure(cause: GuardianError(error: .InvalidPayloadError)))
                return
            }
            request.HTTPBody = body
        }
        
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        headers?.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        
        let task = session.dataTaskWithRequest(request) { data, response, error in
            if let error = error { return callback(.Failure(cause: error)) }
            guard let httpResponse = response as? NSHTTPURLResponse else {
                return callback(.Failure(cause: GuardianError(error: .InvalidResponseError)))
            }
            guard (200..<300).contains(httpResponse.statusCode) else {
                guard let info: [String: AnyObject] = json(data) else {
                    return callback(.Failure(cause: GuardianError(error: .InvalidResponseError, statusCode: httpResponse.statusCode)))
                }
                return callback(.Failure(cause: GuardianError(info: info, statusCode: httpResponse.statusCode)))
            }
            callback(.Success(payload: json(data)))
        }
        task.resume()
    }
}

func json<T>(data: NSData?) -> T? {
    guard let data = data else { return nil }
    let object = try? NSJSONSerialization.JSONObjectWithData(data, options: [])
    return object as? T
}
