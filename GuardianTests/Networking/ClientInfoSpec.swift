// ClientInfoSpec.swift
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

let info = ["CFBundleShortVersionString": "1.0.0"]

class ClientInfoSpec: QuickSpec {

    override class func spec() {

        describe("init(info:)") {
            it("should create a new instance") {
                expect(ClientInfo(info: info)).toNot(beNil())
            }

            it("should set name to fixed value") {
                expect(ClientInfo(info: info)?.name).to(equal("Guardian.swift"))
            }

            it("should set version") {
                expect(ClientInfo(info: info)?.version).to(equal("1.0.0"))
            }

            it("should not create with missing mktg version") {
                expect(ClientInfo(info: [:])).to(beNil())
            }
        }

        describe("asHeader()") {
            let clientInfo = ClientInfo(info: info)!

            it("should return an entry") {
                expect(try? clientInfo.asHeader()).toNot(beEmpty())
            }

            it("should have the correct header name") {
                expect(try? clientInfo.asHeader().keys).to(contain("Auth0-Client"))
            }

            it("should have the correct header value") {
                expect(try? clientInfo.asHeader().values).to(contain("eyJuYW1lIjoiR3VhcmRpYW4uc3dpZnQiLCJ2ZXJzaW9uIjoiMS4wLjAifQ"))
            }

        }
    }
}

