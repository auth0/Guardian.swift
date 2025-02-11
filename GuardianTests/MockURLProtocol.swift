//  MockURLProtocol.swift
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

import Foundation

class MockURLProtocol: URLProtocol {
    
    private static var originalSessionConfigurationImplementation: IMP?
    private static var stubNames = [String]()
    private static var stubs = [String: Stub]()

    private struct Stub {
        let condition: MockURLProtocolCondition
        let response: ((URLRequest) -> MockURLResponse)?
        let error: Error?
    }
    
    private var stubName: String?

    static func stub(name: String, condition: @escaping MockURLProtocolCondition, data: Data? = nil, response: ((URLRequest) -> MockURLResponse)? = nil, error: Error? = nil) {
        stubs[name] = Stub(condition: condition, response: response, error: error)
        stubNames.removeAll { $0 == name }
        stubNames.insert(name, at: 0)
    }

    static func startInterceptingRequests() {
        swizzleURLSessionConfiguration()
    }

    static func stopInterceptingRequests() {
        swizzleURLSessionConfiguration()
        stubs.removeAll()
        stubNames.removeAll()
    }

    override class func canInit(with request: URLRequest) -> Bool {
        return firstSuitableStubName(request: request) != nil
    }
    
    override init(request: URLRequest, cachedResponse: CachedURLResponse?, client: URLProtocolClient?) {
        stubName = MockURLProtocol.firstSuitableStubName(request: request)
        super.init(request: request, cachedResponse: cachedResponse, client: client)
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }

    override func startLoading() {
        guard let stubName, let stub = MockURLProtocol.stubs[stubName] else { return }

        if let response = stub.response?(request).httpResponse(url: url) {
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        }

        if let data = stub.response?(request).data {
            client?.urlProtocol(self, didLoad: data)
        }

        if let error = stub.error {
            client?.urlProtocol(self, didFailWithError: error)
        }

        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {
        
    }
    
    private static func swizzleURLSessionConfiguration() {
        originalSessionConfigurationImplementation = method_getImplementation(class_getClassMethod(URLSessionConfiguration.self, #selector(getter: URLSessionConfiguration.ephemeral))!)
        let originalMethod = class_getClassMethod(URLSessionConfiguration.self, #selector(getter: URLSessionConfiguration.ephemeral))!
        let swizzledMethod = class_getClassMethod(MockURLProtocol.self, #selector(defaultSessionConfiguration))!
        method_exchangeImplementations(originalMethod, swizzledMethod)
    }
    
    @objc class func defaultSessionConfiguration() -> URLSessionConfiguration {
        typealias MyCFunction = @convention(c) (AnyObject, Selector) -> URLSessionConfiguration
        let curriedImplementation = unsafeBitCast(originalSessionConfigurationImplementation, to: MyCFunction.self)
        let configuration = curriedImplementation(MockURLProtocol.self, #selector(getter: URLSessionConfiguration.ephemeral))
        configuration.protocolClasses?.insert(MockURLProtocol.self, at: 0)
        return configuration
    }
    
    private class func firstSuitableStubName(request: URLRequest) -> String? {
        for stubName in stubNames {
            if let stub = stubs[stubName], stub.condition(request) {
                return stubName
            }
        }
        return nil
    }
}
