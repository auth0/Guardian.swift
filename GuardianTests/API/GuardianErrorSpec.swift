// GuardianErrorSpec.swift
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

class GuardianErrorSpec: QuickSpec {

    override class func spec() {

        it("should build with required attributes") {
            expect(GuardianError(code: .invalidNotificationActionIdentifier).code).to(equal(GuardianError.Code.invalidNotificationActionIdentifier.rawValue))
        }

        it("should build with default description") {
            expect(GuardianError(code: .invalidNotificationActionIdentifier).description).to(equal(GuardianError.Code.invalidNotificationActionIdentifier.rawValue))
        }

        describe("Decodable") {

            let decoder = JSONDecoder()

            it("should fail with unknown json") {
                let badJSON = """
                {
                    "key": "value"
                }
                """.data(using: .utf8)!
                expect {
                    return try decoder.decode(GuardianError.self, from: badJSON)
                }.to(throwError())
            }

            it("should load with only errorCode") {
                let code = UUID().uuidString
                let minimalJSON = """
                {
                    "errorCode": "\(code)"
                }
                """.data(using: .utf8)!
                expect(try? decoder.decode(GuardianError.self, from: minimalJSON).code).to(equal(code))
            }

            it("should load description from code") {
                let code = UUID().uuidString
                let minimalJSON = """
                {
                    "errorCode": "\(code)"
                }
                """.data(using: .utf8)!
                expect(try? decoder.decode(GuardianError.self, from: minimalJSON).description).to(equal(code))
            }

            it("should load description from code") {
                let code = UUID().uuidString
                let description = "Something is wrong"
                let minimalJSON = """
                {
                    "errorCode": "\(code)",
                    "description": "\(description)"
                }
                """.data(using: .utf8)!
                expect(try? decoder.decode(GuardianError.self, from: minimalJSON).description).to(equal(description))
            }

            it("should load extra string field") {
                let code = UUID().uuidString
                let randomValue = UUID().uuidString
                let minimalJSON = """
                {
                    "errorCode": "\(code)",
                    "field": "\(randomValue)"
                }
                """.data(using: .utf8)!
                expect(try? decoder.decode(GuardianError.self, from: minimalJSON).info["field"] as? String).to(equal(randomValue))
            }

            it("should load extra int field") {
                let code = UUID().uuidString
                let randomValue = Int(arc4random())
                let minimalJSON = """
                {
                    "errorCode": "\(code)",
                    "field": \(randomValue)
                }
                """.data(using: .utf8)!
                expect(try? decoder.decode(GuardianError.self, from: minimalJSON).info["field"] as? Int).to(equal(randomValue))
            }

            it("should load extra double field") {
                let code = UUID().uuidString
                let randomValue = Double(Date().timeIntervalSince1970)
                let minimalJSON = """
                {
                    "errorCode": "\(code)",
                    "field": \(randomValue)
                }
                """.data(using: .utf8)!
                expect{
                    let field = try! decoder.decode(GuardianError.self, from: minimalJSON).info["field"]
                    return field as? Double
                }.to(beCloseTo(randomValue, within: 0.01))
            }

            it("should not load extra unknown type field") {
                let code = UUID().uuidString
                let minimalJSON = """
                {
                    "errorCode": "\(code)",
                    "field": {}
                }
                """.data(using: .utf8)!
                expect(try! decoder.decode(GuardianError.self, from: minimalJSON).info["field"]).to(beNil())
            }

            it("should load extra int field") {
                let code = UUID().uuidString
                let minimalJSON = """
                {
                    "errorCode": "\(code)",
                    "field": true
                }
                """.data(using: .utf8)!
                expect(try! decoder.decode(GuardianError.self, from: minimalJSON).info["field"] as? Bool).to(beTrue())
            }
        }
    }
}
