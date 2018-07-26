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

/// Default URLSession used to send requests to Guardian API.
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

func decode<T: Decodable>(_ type: T.Type, from data: Data, decoder: JSONDecoder = JSONDecoder()) throws -> T {
    do { return try decoder.decode(type, from: data) }
    catch let error { throw NetworkError(code: .cannotDecodeJSON, cause: error) }
}

func encode<B: Encodable>(body: B, encoder: JSONEncoder = JSONEncoder()) throws -> Data {
    do { return try encoder.encode(body) }
    catch let error { throw NetworkError(code: .cannotEncodeJSON, cause: error) }
}

public struct NetworkOperation<T: Encodable, E: Decodable> {

    let request: URLRequest
    let body: T?
    var session: URLSession
    var observer: NetworkObserver
    var errorMapper: (HTTPURLResponse, Data?) -> Error?

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
        self.session = privateSession
        self.observer = NetworkObserver()
        self.errorMapper = { _, _ in return nil }
    }

    func withURLSession(_ session: URLSession) -> NetworkOperation<T, E> {
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

    public func mapError(transform: @escaping (HTTPURLResponse, Data?) -> Error?) -> NetworkOperation<T, E> {
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
        let task = self.session.dataTask(with: request) {
            callback(self.handle(data: $0, response: $1, error: $2))
        }
        task.resume()
    }

    func handle(data: Data?, response: URLResponse?, error: Error?) -> Result<E> {
        if let error = error {
            return .failure(cause: NetworkError(code: .failedRequest, cause: error))
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            return .failure(cause: NetworkError(code: .failedRequest))
        }

        self.observer.response?(NetworkResponseEvent(data: data, response: httpResponse))

        let statusCode = httpResponse.statusCode
        guard (200..<300).contains(statusCode) else {
            let error = self.errorMapper(httpResponse, data) ?? NetworkError(statusCode: statusCode)
            return .failure(cause: error)
            // Handle 4xx text/plain
            // Handle 429
        }

        guard httpResponse.isJSON else {
            return .failure(cause: NetworkError(code: .invalidResponse, statusCode: statusCode))
        }

        let payloadData = httpResponse.noContent && data == nil ? "{}".data(using: .utf8) : data
        guard let data = payloadData else {
            return .failure(cause: NetworkError(code: .missingResponse, statusCode: statusCode))
        }

        do {
            let body = try decode(E.self, from: data)
            return .success(payload: body)
        } catch let error {
            return .failure(cause: NetworkError(code: .invalidResponse, statusCode: statusCode, cause: error))
        }
    }
}

extension HTTPURLResponse {
    var isJSON: Bool {
        return self.mimeType == "application/json"
    }

    var isText: Bool {
        return self.mimeType == "text/plain"
    }

    var noContent: Bool {
        return self.statusCode == 204
    }
}

public struct NoContent: Decodable {
    public init(from decoder: Decoder) throws {}
}

public struct NetworkError: Error, CustomStringConvertible {
    public let statusCode: Int
    public let description: String
    public let code: Code
    public let cause: Error?

    init(code: Code, description: String? = nil, statusCode: Int = 0, cause: Error? = nil) {
        self.code = code
        self.description = description ?? code.message
        self.statusCode = statusCode
        self.cause = cause
    }

    init(statusCode: Int) {
        self.init(code: .from(statusCode: statusCode), statusCode: statusCode)
    }

    public enum Code: String {
        case cannotEncodeJSON
        case cannotDecodeJSON
        case failedRequest
        case invalidResponse
        case failedResponse
        case missingResponse
        case badRequest
        case notAuthorized
        case rateLimited
        case serverError

        var message: String {
            switch self {
            case .cannotEncodeJSON:
                return "Cannot encode request JSON body"
            case .cannotDecodeJSON:
                return "Cannot decode response JSON body"
            case .failedRequest:
                return "Request failed to be sent"
            case .failedResponse:
                return "Server returned with a non 2XX status code"
            case .invalidResponse:
                return "Server returned a non JSON response"
            case .missingResponse:
                return "No response body was received"
            case .badRequest:
                return "The request was considered invalid by the server"
            case .notAuthorized:
                return "Not authorized or missing authorization"
            case .rateLimited:
                return "Exceeded number of request to API"
            case .serverError:
                return "Server failed to respond"
            }
        }

        static func from(statusCode: Int) -> Code {
            switch statusCode {
            case 400:
                return .badRequest
            case 401, 403:
                return .notAuthorized
            case 429:
                return .rateLimited
            case 500...599:
                return .serverError
            default:
                return .failedRequest
            }
        }
    }
}

extension NetworkError: Equatable {
    public static func == (lhs: NetworkError, rhs: NetworkError) -> Bool {
        return lhs.code == rhs.code && lhs.statusCode == rhs.statusCode
    }
}

struct NetworkRequestEvent: RequestEvent {
    let request: URLRequest
}

struct NetworkResponseEvent: ResponseEvent {
    let data: Data?
    let response: HTTPURLResponse
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
