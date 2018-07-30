// NetworkError.swift
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

/// Network Error
public struct NetworkError: Swift.Error, CustomStringConvertible {
    /// Status code returned from the server or `0` if request failed
    public let statusCode: Int
    /// Description of the error
    public let description: String
    /// Internal error code
    public let code: Code
    /// If the error was triggered by another one
    public let cause: Swift.Error?

    init(code: Code, description: String? = nil, statusCode: Int = 0, cause: Swift.Error? = nil) {
        self.code = code
        self.description = description ?? code.message
        self.statusCode = statusCode
        self.cause = cause
    }

    init(statusCode: Int, description: String? = nil) {
        self.init(code: .from(statusCode: statusCode), description: description, statusCode: statusCode)
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
        case notFound

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
                return "Server returned a response in an unknown format"
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
            case .notFound:
                return "Resource was not found in the server"
            }
        }

        static func from(statusCode: Int) -> Code {
            switch statusCode {
            case 400:
                return .badRequest
            case 404:
                return .notFound
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
