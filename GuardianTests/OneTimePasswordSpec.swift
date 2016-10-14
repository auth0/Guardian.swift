// OneTimePasswordSpec.swift
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

class OneTimePasswordSpec: QuickSpec {

    override func spec() {

        describe("constructor") {

            let period = 30

            it("should return valid sha1 algorithm") {
                let base32Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                let key = Base32.decode(string: base32Secret)!
                expect(TOTP(withKey: key, period: period, algorithm: "sha1")).toNot(beNil())
            }

            it("should return valid sha256 algorithm") {
                let base32Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
                let key = Base32.decode(string: base32Secret)!
                expect(TOTP(withKey: key, period: period, algorithm: "sha256")).toNot(beNil())
            }

            it("should return valid sha512 algorithm") {
                let base32Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="
                let key = Base32.decode(string: base32Secret)!
                expect(TOTP(withKey: key, period: period, algorithm: "sha512")).toNot(beNil())
            }

            it("should fail when using not supported algorithm") {
                let base32Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="
                let key = Base32.decode(string: base32Secret)!
                expect(TOTP(withKey: key, period: period, algorithm: "something")).to(beNil())
            }
        }

        describe("totp") {

            var algorithmName = "sha1"
            var period = 30
            let digits = 8

            beforeEach {
                period = 30
            }

            // Test vector from RFC 6238 https://tools.ietf.org/html/rfc6238#appendix-B
            describe("generate code") {

                let validTOTP = "valid totp"

                sharedExamples(validTOTP) { (context: SharedExampleContext) in
                    let data = context()
                    let code = data["code"] as! String
                    let counter = data["counter"] as! Int
                    let base32Secret = data["key"] as! String
                    var otp: TOTP!

                    beforeEach {
                        algorithmName = data["alg"] as! String
                        let key = Base32.decode(string: base32Secret)!
                        otp = TOTP(withKey: key, period: period, algorithm: algorithmName)
                    }

                    it("should return code '\(code)' for counter '\(counter)'") {
                        expect(otp.generate(digits: digits, counter: counter)).to(equal(code))
                    }
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
        }
    }
}
