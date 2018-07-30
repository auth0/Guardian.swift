// NoContentDecoderSpec.swift
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

class NoContentDecoderSpec: QuickSpec {

    override func spec() {

        describe("fail all operations") {

            it("should fail to decode keyed container") {
                let decoder = NoContentDecoder()
                expect {
                    return try decoder.container(keyedBy: Device.CodingKeys.self)
                }.to(throwError())
            }

            it("should fail to decode with unkeyed container") {
                let decoder = NoContentDecoder()
                expect {
                    return try decoder.unkeyedContainer()
                }.to(throwError())
            }

            it("should fail with single value container") {
                let decoder = NoContentDecoder()
                expect {
                    return try decoder.singleValueContainer()
                }.to(throwError())
            }

            it("should have no coding path") {
                expect(NoContentDecoder().codingPath).to(beEmpty())
            }

            it("should have no user info") {
                expect(NoContentDecoder().userInfo).to(beEmpty())
            }

        }
    }
}
