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

public struct NetworkOperation<T: Encodable, E: Decodable>: Operation {

    let request: URLRequest
    let body: T?
    var session: URLSession = privateSession
    var observer: NetworkObserver = NetworkObserver()
    var errorMapper: (HTTPURLResponse, Data?) -> Swift.Error? = { _, _ in return nil }
    let error: Swift.Error?

    init(method: HTTPMethod, url: URL, error: Swift.Error) {
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue.uppercased()
        self.request = request
        self.body = nil
        self.error = error
    }

    init(method: HTTPMethod, url: URL, headers: [String: String] = [:], body: T? = nil) throws {
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue.uppercased()
        headers
            .merging(try defaultHeaders(hasBody: body != nil)) { old, _ in return old }
            .forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }

        if let body = body { // Fail if its 'GET'
            request.httpBody = try encode(body: body)
        }

        self.body = body
        self.request = request
        self.error = nil
    }

    /**
     Allows to change the URLSession used to perform the requests.
     - parameter session: new URLSession to use to perform requests
     - returns: itself for easy chaining
    */
    public func withURLSession(_ session: URLSession) -> NetworkOperation<T, E> {
        var newSelf = self
        newSelf.session = session
        return newSelf
    }

    /**
     Registers hooks to be called on specific events:
        * on request being sent
        * on response recieved (successful or not)

        - Parameters:
          - request: closure called with request information
          - response: closure called with response and data
        - Returns: itself for chaining
    */
    public func on(request: OnRequestEvent? = nil, response: OnResponseEvent? = nil) -> NetworkOperation<T, E> {
        var newSelf = self
        newSelf.observer = NetworkObserver(request: request ?? self.observer.request, response: response ?? self.observer.response)
        return newSelf
    }

    /**
     Allows to return a custom error when HTTP response is not 2xx. If nil is returned a default error will be used.
     - parameter transform: closure that will be executed when a custom error is needed. It will receive the response and its body as parameters
     - returns: istelf for chaining
    */
    public func mapError(transform: @escaping (HTTPURLResponse, Data?) -> Swift.Error?) -> NetworkOperation<T, E> {
        var newSelf = self
        newSelf.errorMapper = transform
        return newSelf
    }

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is received
     */
    public func start(callback: @escaping (Result<E>) -> ()) {
        self.observer.request?(NetworkRequestEvent(request: request))
        if let cause = self.error {
            return callback(.failure(cause: cause))
        }
        let task = self.session.dataTask(with: request) {
            callback(self.handle(payload: $0, response: $1, error: $2))
        }
        task.resume()
    }

    func handle(payload: Data?, response: URLResponse?, error: Swift.Error?) -> Result<E> {
        if let error = error {
            return .failure(cause: NetworkError(code: .failedRequest, cause: error))
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            return .failure(cause: NetworkError(code: .failedRequest))
        }

        let responseEvent = NetworkResponseEvent(data: payload, response: httpResponse, rateLimit: RateLimit(response: httpResponse))
        self.observer.response?(responseEvent)

        let statusCode = httpResponse.statusCode
        guard (200..<300).contains(statusCode) else {
            let error: Swift.Error = self.errorMapper(httpResponse, payload)
                ?? NetworkError(statusCode: statusCode, description: message(from: httpResponse, data: payload))
            return .failure(cause: error)
        }

        guard httpResponse.noContent || payload != nil else {
            return .failure(cause: NetworkError(code: .missingResponse, statusCode: statusCode))
        }

        guard httpResponse.isJSON || httpResponse.noContent else {
            return .failure(cause: NetworkError(code: .invalidResponse, statusCode: statusCode))
        }

        do {
            let body = try decode(E.self, from: payload)
            return .success(payload: body)
        } catch let error {
            return .failure(cause: NetworkError(code: .invalidResponse, statusCode: statusCode, cause: error))
        }
    }

    func message(from response: HTTPURLResponse, data: Data?) -> String? {
        guard response.isText, let data = data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

// MARK:- Events

struct NetworkRequestEvent: RequestEvent {
    let request: URLRequest
}

struct NetworkResponseEvent: ResponseEvent {
    let data: Data?
    let response: HTTPURLResponse
    let rateLimit: RateLimit?
}

// MARK:- Debugging

extension NetworkOperation: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        return "\(self.request.httpMethod!) \(self.request.url!.absoluteString)"
    }

    public var debugDescription: String {
        var description = "\(self.request.httpMethod!) \(self.request.url!.absoluteString)\n"
        self.request.allHTTPHeaderFields?.forEach { description.append("\($0): \($1)\n") }
        description.append("\n")
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        if let payload = self.body,
            let data = try? encode(body: payload, encoder: encoder),
            let json = String(data: data, encoding: .utf8) {
            description.append(json.replacingOccurrences(of: "\\n", with: "\n"))
        }
        return description
    }

}

// MARK:- Bundle Hook

class _BundleGrapple: NSObject {}

// MARK:- Defaults

/// Default URLSession used to send requests.
private let privateSession: URLSession =  {
    let config = URLSessionConfiguration.ephemeral
    config.requestCachePolicy = .reloadIgnoringLocalCacheData
    config.urlCache = nil

    return URLSession.init(configuration: config)
}()

func defaultHeaders(hasBody: Bool) throws -> [String: String] {
    let info = Bundle(for: _BundleGrapple.classForCoder()).infoDictionary ?? [:]
    let clientInfo = ClientInfo(info: info)
    let telemetry = try clientInfo?.asHeader() ?? [:]
    let content = hasBody ? ["Content-Type": "application/json"] : [:]
    return telemetry.merging(content) { _, new in new }
}

