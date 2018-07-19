// AuthenticationSource.swift
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

struct AuthenticationSource: Source, CustomDebugStringConvertible, CustomStringConvertible {

    class NamedSource: NSObject, OS, Browser {
        let name: String
        let version: String?

        init(name: String, version: String?) {
            self.name = name
            self.version = version
        }
    }

    let os: OS?
    let browser: Browser?

    init?(fromJSON json: Any?) {
        guard let source = json as? [String: Any] else {
            return nil
        }

        let browser: Browser?
        let os: OS?
        if let data = source["b"] as? [String: Any], let name = data["n"] as? String {
            let version = data["v"] as? String
            browser = NamedSource(name: name, version: version)
        } else {
            browser = nil
        }
        if let data = source["os"] as? [String: Any], let name = data["n"] as? String {
            let version = data["v"] as? String
            os = NamedSource(name: name, version: version)
        } else {
            os = nil
        }

        if os == nil && browser == nil {
            return nil
        }
        self.os = os
        self.browser = browser
    }

    var description: String {
        let osName = self.os?.name ?? "Unknown OS"
        let osVersion = self.os?.version != nil ? "(\(String(describing: self.os?.version))" : ""
        let browserName = self.browser?.name ?? "Unknown Browser"
        let browserVersion = self.browser?.version != nil ? "(\(String(describing: self.browser?.version))" : ""
        return "\(osName) \(osVersion)".trimmingCharacters(in: .whitespaces) + " \(browserName) \(browserVersion)".trimmingCharacters(in: .whitespaces)
    }

    var debugDescription: String {
        return self.description
    }
}
