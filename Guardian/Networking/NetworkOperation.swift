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

func defaultHeaders(hasBody: Bool) throws -> [String: String] {
    let info = Bundle(for: _BundleGrapple.classForCoder()).infoDictionary ?? [:]
    let clientInfo = ClientInfo(info: info)
    let telemetry = try clientInfo?.asHeader() ?? [:]
    let content = hasBody ? ["Content-Type": "application/json"] : [:]
    return telemetry.merging(content) { _, new in new }
}

func encode<B: Encodable>(body: B, encoder: JSONEncoder = JSONEncoder()) throws -> Data {
    do {
        return try encoder.encode(body)
    }
    catch let error { throw GuardianError.invalidPayload(cause: error) }
}

public struct NetworkOperation<B: Encodable, T: Decodable> {

    let request: URLRequest
    let body: B?

    init(method: HTTPMethod, url: URL, headers: [String: String] = [:], body: B? = nil) throws {
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue.uppercased()
        headers
            .merging(try defaultHeaders(hasBody: body != nil)) { old, _ in return old }
            .forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }

        if let body = body {
            request.httpBody = try encode(body: body)
        }
        self.body = body
        self.request = request
    }

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is received
     */
    public func start(callback: @escaping (Result<T>) -> ()) {
        
    }
}

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

enum HTTPMethod: String {
    case get
    case post
    case patch
    case delete
}
