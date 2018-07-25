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
                let value = UUID().uuidString
                let body = ["id": value]
                let json = "{\"id\":\"\(value)\"}".data(using: .utf8)
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

        
    }
}
