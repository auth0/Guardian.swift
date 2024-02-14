// RequestSpec.swift
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


class RequestSpec: QuickSpec {

    override class func spec() {
        let url = URL(string: "https://auth0.com")!

        describe("wrapping") {

            var session: MockNSURLSession!

            beforeEach {
                session = MockNSURLSession()
            }

            it("should provide custom error builder") {
                let request: Request<String, String> = Request.new(method: .get, url: url)
                let response = http(statusCode: 400)
                let data = "{\"errorCode\": \"random\"}".data(using: .utf8)
                expect(request.request.errorMapper(response, data)).toNot(beNil())
            }

            it("should start request") {
                session.a0_response = http(statusCode: 204)
                let request: Request<[String: String], String> = Request.new(method: .get, url: url).withURLSession(session)
                waitUntil { done in
                    request.start { _ in done() }
                }
            }

            it("should register for request events") {
                let request: Request<String, String> = Request.new(method: .get, url: url)
                waitUntil { done in
                    request
                        .on(request: {_ in done() })
                        .start { _ in }
                }
            }

            it("should register for response events") {
                session.a0_response = http(statusCode: 200)
                let request: Request<String, String> = Request.new(method: .get, url: url).withURLSession(session)
                waitUntil { done in
                    request
                        .on(response: { _ in done() })
                        .start { _ in }
                }
            }

            it("should allow to map errors") {
                let error = MockError()
                session.a0_response = http(statusCode: 400)
                session.a0_data = "{\"errorCode\": \"custom\"}".data(using: .utf8)
                let request: Request<[String: String], String> = Request.new(method: .post, url: url).withURLSession(session)
                waitUntil { done in
                    request
                        .mapError { _, _ in
                            done()
                            return error
                        }
                        .start { result in
                            expect({
                                guard case .failure(let actual as MockError) = result, error == actual else {
                                    return .failed(reason: "not a failure with mapped error")
                                }
                                return .succeeded
                            }).to(succeed())
                        }
                }
            }

            it("should delegate description") {
                let r: Request<[String: String], String> = Request.new(method: .post, url: url)
                expect(r.description).to(equal(r.request.description))
            }

            it("should delegate debug description") {
                let r: Request<[String: String], String> = Request.new(method: .post, url: url)
                expect(r.debugDescription).to(equal(r.request.debugDescription))
            }

        }
    }
}
