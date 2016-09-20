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

            // test vector from https://tools.ietf.org/html/rfc4648#section-10
            describe("decode") {

                let validBase32Encoding = "valid base32 encoding"

                sharedExamples(validBase32Encoding) { (context: SharedExampleContext) in
                    let data = context()
                    let encoded = data["encoded"] as! String
                    let decoded = data["decoded"] as! NSData

                    it("should return data '\(decoded)' for string '\(encoded)'") {
                        expect(NSData(fromBase32String: encoded)).to(equal(decoded))
                    }
                }

                context("rfc4648") {
                    let f: UInt8 = 0x66
                    let o: UInt8 = 0x6F
                    let b: UInt8 = 0x62
                    let a: UInt8 = 0x61
                    let r: UInt8 = 0x72
                    itBehavesLike(validBase32Encoding) { ["encoded": ""                , "decoded": NSData(bytes: [], length: 0)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MY======"        , "decoded": NSData(bytes: [f], length: 1)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MZXQ===="        , "decoded": NSData(bytes: [f,o], length: 2)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MZXW6==="        , "decoded": NSData(bytes: [f,o,o], length: 3)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MZXW6YQ="        , "decoded": NSData(bytes: [f,o,o,b], length: 4)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MZXW6YTB"        , "decoded": NSData(bytes: [f,o,o,b,a], length: 5)] }
                    itBehavesLike(validBase32Encoding) { ["encoded": "MZXW6YTBOI======", "decoded": NSData(bytes: [f,o,o,b,a,r], length: 6)] }
                }
            }
        }
    }
}
