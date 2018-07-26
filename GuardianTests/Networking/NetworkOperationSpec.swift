// NetworkOperationSpec.swift
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

import Quick
import Nimble
@testable import Guardian

let url = URL(string: "https://auth0.com")!
class NetworkOperationSpec: QuickSpec {

    override func spec() {

        func new(method: HTTPMethod = .get, url: URL = url, headers: [String: String] = [:], body: [String: String]? = nil) -> NetworkOperation<[String: String], String> {
            return try! NetworkOperation(method: method, url: url, headers: headers, body: body)
        }

        var basicJSON: [String: String]!
        var basicJSONString: String!

        beforeEach {
            basicJSON = ["key": UUID().uuidString]
            basicJSONString = try! String(data: JSONEncoder().encode(basicJSON), encoding: .utf8)
        }

        describe("init(method:, url:, headers:, body:)") {

            it("should create with mandatory only parameters") {
                expect {
                    try NetworkOperation(method: .get, url: url) as NetworkOperation<String, String>
                }.toNot(throwError())
            }

            let methods: [String: HTTPMethod] = [
                "GET": .get,
                "POST": .post,
                "PATCH": .patch,
                "DELETE": .delete
            ]
            methods.forEach {
                let entry = $0
                it("should have a request with method set to \(entry.key)") {
                    expect(new(method: entry.value).request.httpMethod).to(equal(entry.key))
                }
            }

            it("should have a request with url set") {
                expect(new(url: url).request.url).to(equal(url))
            }

            it("should have a request with headers") {
                let key = "X-Custom-Tracker"
                let value = UUID().uuidString
                expect(new(headers: [key: value]).request.value(forHTTPHeaderField: key)).to(equal(value))
            }

            it("should have a request with telemetry header") {
                let key = "Auth0-Client"
                expect(new().request.value(forHTTPHeaderField: key)).toNot(beNil())
            }

            it("should not have a request with content header") {
                let key = "Content-Type"
                expect(new().request.value(forHTTPHeaderField: key)).to(beNil())
            }

            it("should have a request with 'application/json' content") {
                let key = "Content-Type"
                expect(new(body: ["KEY": "VALUE"]).request.value(forHTTPHeaderField: key)).to(equal("application/json"))
            }

            it("should have a request with telemetry header and client info") {
                expect({
                    let key = "Auth0-Client"
                    let version = Bundle.main.infoDictionary!["CFBundleShortVersionString"] as! String
                    let expected = ClientInfo(name: "Guardian.swift", version: version)
                    let decoder = JSONDecoder()
                    guard let value = new().request.value(forHTTPHeaderField: key) else {
                        return .failed(reason: "missing auth0-client value")
                    }
                    guard let data = Data(base64URLEncoded: value), let actual = try? decoder.decode(ClientInfo.self, from: data) else {
                        return .failed(reason: "invalid auth0-client value \(value)")
                    }
                    guard actual == expected else {
                        return .failed(reason: "expected auth0-client with \(expected) but got \(actual)")
                    }
                    return .succeeded

                }).to(succeed())
            }

            it("should have no body") {
                expect(new().request.httpBody).to(beNil())
            }

            it("should have a JSON body") {
                let body = basicJSON
                let json = basicJSONString.data(using: .utf8)
                expect(new(body: body).request.httpBody).to(equal(json))
            }
        }

        describe("withURLSession()") {

            it("should have a session by default") {
                expect(new().session).toNot(beNil())
            }

            it("should allow to override URLSession") {
                let session = URLSession.shared
                expect(new().withURLSession(session).session).to(equal(session))
            }

        }

        describe("start(callback:)") {

            var session: MockNSURLSession!
            var request: SyncRequest<[String: String]>!

            beforeEach {
                session = MockNSURLSession()
                request = SyncRequest(session: session)
            }

            it("should fail if request fails") {
                let error: Error = NetworkError(code: .cannotDecodeJSON)
                session.a0_error = error
                request.start()
                expect(request.result).toEventually(beFailure())
            }

            it("should fail with non-http response") {
                let error = NetworkError(code: .failedRequest)
                session.a0_response = URLResponse()
                request.start()
                expect(request.result).toEventually(beFailure(with: error))
            }

            it("should fail when status code is not 2xx") {
                let error = NetworkError(code: .serverError, statusCode: 500)
                session.a0_response = http(statusCode: 500)
                request.start()
                expect(request.result).toEventually(beFailure(with: error))
            }

            it("should fail when status code is 200 with no data") {
                let error = NetworkError(code: .missingResponse, statusCode: 200)
                session.a0_response = http(statusCode: 200)
                session.a0_data = nil
                request.start()
                expect(request.result).toEventually(beFailure(with: error))
            }

            it("should fail when payload is not json") {
                let error = NetworkError(code: .invalidResponse, statusCode: 200)
                session.a0_response = http(statusCode: 200)
                session.a0_data = Data()
                request.start()
                expect(request.result).toEventually(beFailure(with: error))
            }

            it("should fail when mime type is not json") {
                let error = NetworkError(code: .invalidResponse, statusCode: 200)
                session.a0_response = http(statusCode: 200, headers: nil)
                session.a0_data = basicJSONString.data(using: .utf8)
                request.start()
                expect(request.result).toEventually(beFailure(with: error))
            }

            it("should succeed with 204 and no content") {
                session.a0_response = http(statusCode: 204)
                session.a0_data = nil
                let request: SyncRequest<NoContent> = SyncRequest(session: session)
                request.start()
                expect(request.result).toEventually(beSuccess())
            }

            it("should ignore data when status is 204") {
                session.a0_response = http(statusCode: 204)
                session.a0_data = basicJSONString.data(using: .utf8)
                let request: SyncRequest<NoContent> = SyncRequest(session: session)
                request.start()
                expect(request.result).toEventually(beSuccess())
            }

            it("should succeed with payload") {
                session.a0_response = http(statusCode: 200)
                session.a0_data = basicJSONString.data(using: .utf8)
                request.start()
                expect(request.result).toEventually(beSuccess(with: basicJSON))
            }

            it("should succeed with custom decodable") {
                let response = MockResponse(key: UUID().uuidString)
                session.a0_response = http(statusCode: 200)
                session.a0_data = "{\"key\": \"\(response.key)\"}".data(using: .utf8)
                let request: SyncRequest<MockResponse> = SyncRequest(session: session)
                request.start()
                expect(request.result).toEventually(beSuccess(with: response))
            }

        }
    }
}

func http(statusCode: Int = 200, headers: [String: String]? = ["Content-Type": "application/json"]) -> HTTPURLResponse {
    return HTTPURLResponse(url: url, statusCode: statusCode, httpVersion: nil, headerFields: headers)!
}

struct MockResponse: Decodable, Equatable {
    let key: String
}

class SyncRequest<T: Decodable> {
    let request: NetworkOperation<[String: String], T>
    var result: Result<T>? = nil

    init(session: URLSession) {
        self.request = try! NetworkOperation(method: .get, url: url).withURLSession(session)
    }

    func start() -> () {
        self.request.start { self.result = $0 }
    }
}

func beSuccess<T: Equatable>(with payload: T) -> Predicate<Result<T>> {
    return Predicate.define("be a success result with \(payload)") { exp, msg in
        guard let result = try exp.evaluate(), case .success(let actual) = result else {
            return PredicateResult(status: .doesNotMatch, message: msg)
        }
        return PredicateResult(bool: actual == payload, message: msg)
    }
}

func beSuccess<T>() -> Predicate<Result<T>> {
    return Predicate.define("be a success result of \(T.self)") { exp, msg in
        guard let result = try exp.evaluate(), case .success = result else {
            return PredicateResult(status: .doesNotMatch, message: msg)
        }
        return PredicateResult(status: .matches, message: msg)
    }
}

func beFailure<T>() -> Predicate<Result<T>> {
    return Predicate.define("be a failure result of network operation") { exp, msg in
        guard let result = try exp.evaluate(), case .failure = result else {
            return PredicateResult(status: .doesNotMatch, message: msg)
        }
        return PredicateResult(status: .matches, message: msg)
    }
}

func beFailure<T>(with cause: NetworkError) -> Predicate<Result<T>> {
    return Predicate.define("be a failure result of network operation w/ error \(cause)") { exp, msg in
        guard let result = try exp.evaluate(),
            case .failure(let actual) = result,
            let error = actual as? NetworkError else {
                return PredicateResult(status: .doesNotMatch, message: msg)
        }
        return PredicateResult(bool: error == cause, message: msg)
    }
}
