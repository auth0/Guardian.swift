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

        fdescribe("init(method:, url:, headers:, body:)") {

            func new(method: HTTPMethod = .get, url: URL = url, headers: [String: String] = [:]) -> NetworkOperation<String> {
                return try! NetworkOperation(method: method, url: url, headers: headers)
            }

            it("should create with mandatory only parameters") {
                expect {
                    try NetworkOperation(method: .get, url: url) as NetworkOperation<String>
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
        }
    }
}
