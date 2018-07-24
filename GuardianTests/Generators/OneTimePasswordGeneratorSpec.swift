// OneTimePasswordGeneratorSpec.swift
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
import Guardian

class OneTimePasswordGeneratorSpec: QuickSpec {

    override func spec() {
        describe("totp") {

            var algorithmName = "sha1"
            var period = 30
            let digits = 8

            beforeEach {
                period = 30
            }

            // Test vector from RFC 6238 https://tools.ietf.org/html/rfc6238#appendix-B
            describe("new(time:, period:)") {

                let validTOTP = "rfc totp"

                sharedExamples(validTOTP) { (context: SharedExampleContext) in
                    let data = context()
                    let code = data["code"] as! String
                    let counter = data["counter"] as! Int
                    let base32Secret = data["key"] as! String
                    var otp: TOTP!

                    beforeEach {
                        algorithmName = data["alg"] as! String
                        otp = try! Guardian.totp(base32Secret: base32Secret, algorithm: algorithmName, digits: digits)
                    }

                    it("should return code '\(code)' for counter '\(counter)'") {
                        expect(otp.new(time: TimeInterval(counter), period: period)).to(equal(code))
                    }
                }

                let base32Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                let algorithm = "sha1"
                let otp = try! Guardian.totp(base32Secret: base32Secret, algorithm: algorithm)

                it("should default to 30 sec period") {
                    expect(otp.new(time: 49)).to(equal("287082"))
                }

                it("should default to current date") {
                    expect(otp.new()).toNot(beNil())
                }

                context("sha1") {
                    let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                    let alg = "sha1"
                    itBehavesLike(validTOTP) { ["counter": 59,          "code": "94287082", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 1111111109,  "code": "07081804", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 1111111111,  "code": "14050471", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 1234567890,  "code": "89005924", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 2000000000,  "code": "69279037", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 20000000000, "code": "65353130", "alg": alg, "key": key] }
                }

                context("sha256") {
                    let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
                    let alg = "sha256"
                    itBehavesLike(validTOTP) { ["counter": 59,          "code": "46119246", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 1111111109,  "code": "68084774", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 1111111111,  "code": "67062674", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 1234567890,  "code": "91819424", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 2000000000,  "code": "90698825", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 20000000000, "code": "77737706", "alg": alg, "key": key] }
                }

                context("sha512") {
                    let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="
                    let alg = "sha512"
                    itBehavesLike(validTOTP) { ["counter": 59,          "code": "90693936", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 1111111109,  "code": "25091201", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 1111111111,  "code": "99943326", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 1234567890,  "code": "93441116", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 2000000000,  "code": "38618901", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 20000000000, "code": "47863826", "alg": alg, "key": key] }
                }
            }

            // Test vector from RFC 4226 https://tools.ietf.org/html/rfc4226#page-32
            describe("new(counter:)") {

                let validTOTP = "rfc hotp"

                sharedExamples(validTOTP) { (context: SharedExampleContext) in
                    let data = context()
                    let code = data["code"] as! String
                    let counter = data["counter"] as! Int
                    let keyString = data["key"] as! String
                    var otp: HOTP!

                    beforeEach {
                        algorithmName = data["alg"] as! String
                        let key = keyString.data(using: .utf8)!
                        otp = try! Guardian.hotp(secret: key, algorithm: algorithmName, digits: 6)
                    }

                    it("should return code '\(code)' for counter '\(counter)'") {
                        expect(otp.new(counter: counter)).to(equal(code))
                    }
                }

                context("sha1") {
                    let key = "12345678901234567890"
                    let alg = "sha1"
                    itBehavesLike(validTOTP) { ["counter": 0, "code": "755224", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 1, "code": "287082", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 2, "code": "359152", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 3, "code": "969429", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 4, "code": "338314", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 5, "code": "254676", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 6, "code": "287922", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 7, "code": "162583", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 8, "code": "399871", "alg": alg, "key": key] }
                    itBehavesLike(validTOTP) { ["counter": 9, "code": "520489", "alg": alg, "key": key] }
                }
            }
        }
    }
}
