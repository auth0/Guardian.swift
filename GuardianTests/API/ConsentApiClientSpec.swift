// ConsentAPIClientSpec.swift
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

class ConsentAPIClientSpec: QuickSpec {
    
    override class func spec() {
        describe("init") {
            it("should correctly handle legacy url") {
                let consent = ConsentAPIClient(baseConsentUrl: URL(string: "https://samples.guardian.en.auth0.com")!)
                expect(consent.url).to(equal(URL(string: "https://samples.en.auth0.com/rich-consents")!))
            }
            
            it("should should correctly handle new url") {
                let consent = ConsentAPIClient(baseConsentUrl: URL(string: "https://samples.en.auth0.com")!)
                expect(consent.url).to(equal(URL(string: "https://samples.en.auth0.com/rich-consents")!))
            }
            
            it("should should correctly handle new url with guardian word in it") {
                let consent = ConsentAPIClient(baseConsentUrl: URL(string: "https://sample.guardian.samples.en.auth0.com")!)
                expect(consent.url).to(equal(URL(string: "https://sample.guardian.samples.en.auth0.com/rich-consents")!))
            }
            
            it("should take url as is if parameter is set") {
                let consent = ConsentAPIClient(baseConsentUrl: URL(string: "https://sample.samples.guardian.en.auth0.com/test")!, shouldModifyURL: false)
                expect(consent.url).to(equal(URL(string: "https://sample.samples.guardian.en.auth0.com/test")!))
            }
        }
    }
}
