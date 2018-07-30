// Operation.swift
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

public protocol Operation: CustomDebugStringConvertible, CustomStringConvertible {
    associatedtype T
    associatedtype E

    /**
     Allows to change the URLSession used to perform the requests.
     - parameter session: new URLSession to use to perform requests
     - returns: itself for easy chaining
     */
    func withURLSession(_ session: URLSession) -> Self

    /**
     Registers hooks to be called on specific events:
     * on request being sent
     * on response recieved (successful or not)

     - Parameters:
     - request: closure called with request information
     - response: closure called with response and data
     - Returns: itself for chaining
     */
    func on(request: OnRequestEvent?, response: OnResponseEvent?) -> Self

    /**
     Allows to return a custom error when HTTP response is not 2xx. If nil is returned a default error will be used.
     - parameter transform: closure that will be executed when a custom error is needed. It will receive the response and its body as parameters
     - returns: istelf for chaining
     */
    func mapError(transform: @escaping (HTTPURLResponse, Data?) -> Swift.Error?) -> Self

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is received
     */
    func start(callback: @escaping (Result<E>) -> ())
}
