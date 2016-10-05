// RequestSpec.swift
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
import OHHTTPStubs

@testable import Guardian

private let ValidMethod = "GET"
private let ErrorCode = 1

class RequestSpec: QuickSpec {
    
    override func spec() {
        
        describe("constructor") {
            
            it("should set url") {
                waitUntil(timeout: Timeout) { done in
                    let session = MockNSURLSession(data: nil, response: nil, error: nil)
                    Request<Void>(session: session, method: "PATCH", url: ValidURL)
                        .start { _ in
                            let request = session.a0_request!
                            expect(request.URL).to(equal(ValidURL))
                            done()
                    }
                }
            }
            
            it("should set method") {
                waitUntil(timeout: Timeout) { done in
                    let session = MockNSURLSession(data: nil, response: nil, error: nil)
                    Request<Void>(session: session, method: "PATCH", url: ValidURL)
                        .start { _ in
                            let request = session.a0_request!
                            expect(request.HTTPMethod).to(equal("PATCH"))
                            done()
                    }
                }
            }
            
            it("should set payload") {
                waitUntil(timeout: Timeout) { done in
                    let session = MockNSURLSession(data: nil, response: nil, error: nil)
                    let payload = [
                        "someField": "someValue",
                        "someOtherField": "someOtherValue"
                    ]
                    let serializedPayload = try? NSJSONSerialization.dataWithJSONObject(payload, options: [])
                    Request<Void>(session: session, method: "PATCH", url: ValidURL, payload: payload)
                        .start { _ in
                            let request = session.a0_request!
                            expect(request.HTTPBody).to(equal(serializedPayload))
                            done()
                    }
                }
            }
            
            it("should set default headers") {
                waitUntil(timeout: Timeout) { done in
                    let session = MockNSURLSession(data: nil, response: nil, error: nil)
                    Request<Void>(session: session, method: "PATCH", url: ValidURL)
                        .start { _ in
                            let request = session.a0_request!
                            expect(request.valueForHTTPHeaderField("Content-Type")).to(equal("application/json"))
                            done()
                    }
                }
            }
            
            it("should set custom headers") {
                waitUntil(timeout: Timeout) { done in
                    let session = MockNSURLSession(data: nil, response: nil, error: nil)
                    Request<Void>(session: session, method: "PATCH", url: ValidURL, headers: ["SomeHeaderName": "SomeHeaderValue"])
                        .start { _ in
                            let request = session.a0_request!
                            expect(request.valueForHTTPHeaderField("SomeHeaderName")).to(equal("SomeHeaderValue"))
                            done()
                    }
                }
            }
        }
        
        describe("callback") {
            
            it("should fail with forwarded error when there is an NSError") {
                waitUntil(timeout: Timeout) { done in
                    let session = MockNSURLSession(data: nil, response: nil, error: NSError(domain: "auth0.com", code: ErrorCode, userInfo: nil))
                    Request<Void>(session: session, method: ValidMethod, url: ValidURL)
                        .start { result in
                            expect(result).to(haveNSError(withErrorCode: ErrorCode))
                            done()
                    }
                }
            }
            
            it("should fail with 'invalid response' when the response is not a NSHTTPURLResponse") {
                waitUntil(timeout: Timeout) { done in
                    let session = MockNSURLSession(data: nil, response: NSURLResponse(), error: nil)
                    Request<Void>(session: session, method: ValidMethod, url: ValidURL)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: GuardianError.invalidResponse.errorCode))
                            done()
                    }
                }
            }
            
            it("should fail with 'invalid response' when the response status code is not in [200,300) and body is nil") {
                waitUntil(timeout: Timeout) { done in
                    let response = NSHTTPURLResponse(URL: ValidURL, statusCode: 404, HTTPVersion: nil, headerFields: nil)
                    let session = MockNSURLSession(data: nil, response: response, error: nil)
                    Request<Void>(session: session, method: ValidMethod, url: ValidURL)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: GuardianError.invalidResponse.errorCode, andStatusCode: 404))
                            done()
                    }
                }
            }
            
            it("should fail with 'invalid response' when the response status code is not in [200,300) and body includes unparseable data") {
                waitUntil(timeout: Timeout) { done in
                    let response = NSHTTPURLResponse(URL: ValidURL, statusCode: 401, HTTPVersion: nil, headerFields: nil)
                    let data = NSData(base64EncodedString: "SomeInvalidJSON", options: [])
                    let session = MockNSURLSession(data: data, response: response, error: nil)
                    Request<Void>(session: session, method: ValidMethod, url: ValidURL)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: GuardianError.invalidResponse.errorCode, andStatusCode: 401))
                            done()
                    }
                }
            }
            
            it("should fail with 'server error info' when the response status code is not in [200,300) and body includes error") {
                waitUntil(timeout: Timeout) { done in
                    let response = NSHTTPURLResponse(URL: ValidURL, statusCode: 401, HTTPVersion: nil, headerFields: nil)
                    let data = try? NSJSONSerialization.dataWithJSONObject([
                        "errorCode": "SomeErrorCode"
                        ], options: [])
                    let session = MockNSURLSession(data: data, response: response, error: nil)
                    Request<Void>(session: session, method: ValidMethod, url: ValidURL)
                        .start { result in
                            expect(result).to(haveGuardianError(withErrorCode: "SomeErrorCode", andStatusCode: 401))
                            done()
                    }
                }
            }
            
            it("should succeed with empty payload") {
                waitUntil(timeout: Timeout) { done in
                    let response = NSHTTPURLResponse(URL: ValidURL, statusCode: 201, HTTPVersion: nil, headerFields: nil)
                    let session = MockNSURLSession(data: nil, response: response, error: nil)
                    Request<Void>(session: session, method: ValidMethod, url: ValidURL)
                        .start { result in
                            expect(result).to(beSuccess())
                            done()
                    }
                }
            }
            
            it("should succeed with parsed payload") {
                waitUntil(timeout: Timeout) { done in
                    let response = NSHTTPURLResponse(URL: ValidURL, statusCode: 201, HTTPVersion: nil, headerFields: nil)
                    let payload: [String: String] = [
                        "someField": "someValue"
                    ]
                    let data = try? NSJSONSerialization.dataWithJSONObject(payload, options: [])
                    let session = MockNSURLSession(data: data, response: response, error: nil)
                    Request<[String: String]>(session: session, method: ValidMethod, url: ValidURL)
                        .start { result in
                            expect(result).to(beSuccess(withData: ["someField": "someValue"]))
                            done()
                    }
                }
            }
        }
    }
}
