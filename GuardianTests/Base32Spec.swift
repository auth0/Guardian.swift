// Base32Spec.swift
//
// Copyright (c) 2016 Auth0 (http://auth0.com)
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

class Base32Spec: QuickSpec {

    override func spec() {

        describe("base32") {

            describe("decode") {

                it("should return nil for invalid input") {
                    expect(Base32.decode(string: "somethingNotBase32encoded!?")).to(beNil())
                }
            }

            describe("test vectors") {

                let validBase32Encoding = "valid base32 encoding"

                sharedExamples(validBase32Encoding) { (context: SharedExampleContext) in
                    let data = context()
                    let encoded = data["encoded"] as! String
                    let decoded = data["decoded"] as! Data

                    it("should return data '\(decoded)' for string '\(encoded)'") {
                        expect(Base32.decode(string: encoded)).to(equal(decoded))
                    }
                }

                // test vector from https://tools.ietf.org/html/rfc4648#section-10
                context("rfc4648") {
                    let f: UInt8 = 0x66
                    let o: UInt8 = 0x6F
                    let b: UInt8 = 0x62
                    let a: UInt8 = 0x61
                    let r: UInt8 = 0x72
                    itBehavesLike(validBase32Encoding) { ["encoded": ""                , "decoded": Data(bytes: UnsafePointer<UInt8>([]), count: 0)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MY======"        , "decoded": Data(bytes: UnsafePointer<UInt8>([f]), count: 1)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MZXQ===="        , "decoded": Data(bytes: UnsafePointer<UInt8>([f,o]), count: 2)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MZXW6==="        , "decoded": Data(bytes: UnsafePointer<UInt8>([f,o,o]), count: 3)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MZXW6YQ="        , "decoded": Data(bytes: UnsafePointer<UInt8>([f,o,o,b]), count: 4)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MZXW6YTB"        , "decoded": Data(bytes: UnsafePointer<UInt8>([f,o,o,b,a]), count: 5)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MZXW6YTBOI======", "decoded": Data(bytes: UnsafePointer<UInt8>([f,o,o,b,a,r]), count: 6)] }
                }
            }
        }
    }
}
