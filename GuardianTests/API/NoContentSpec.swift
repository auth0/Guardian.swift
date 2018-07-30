// NoContentSpec.swift
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

class NoContentSpec: QuickSpec {

    override func spec() {

        describe("Decodable") {

            it("should load from NoContent decoder") {
                expect(try? NoContent(from: NoContentDecoder())).toNot(beNil())
            }

            it("should load from JSON decoder with data") {
                expect(try? JSONDecoder().decode(NoContent.self, from: "{\"key\":\"value\"}".data(using: .utf8)!)).toNot(beNil())
            }

        }

        describe("Encodable") {

            it("should fail to encode json") {
                expect {
                    return try JSONEncoder().encode(NoContent())
                }.to(throwError())
            }
        }
    }
}
