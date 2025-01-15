// SigningKeyStorageSpec.swift
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

class SigningKeyStorageSpec: QuickSpec {
    override class func spec() {
        describe("storeInKeychain(with:, accessible:)") {

            var tag: String!

            beforeEach {
                tag = KeychainBot.shared.newTag()
            }

            afterEach {
                KeychainBot.shared.clean()
            }

            it("should store key with tag") {
                let key = try! DataRSAPrivateKey.new().storeInKeychain(with: tag)
                expect(key.secKey).toNot(beNil())
            }

            it("should create and store key with tag") {
                let key = try! KeychainRSAPrivateKey.new(with: tag)
                expect(key.secKey).toNot(beNil())
            }

            it("should be accesible") {
                let _ = try! DataRSAPrivateKey.new().storeInKeychain(with: tag)
                let same = try! KeychainRSAPrivateKey(tag: tag)
                expect(same.secKey).toNot(beNil())
            }

            it("should allow to specify accessibility") {
                expect({
                    try! DataRSAPrivateKey.new().storeInKeychain(with: tag, accessible: .afterFirstUnlock)
                }).toNot(raiseException())
            }
        }
    }
}

class KeychainBot {

    static let shared = KeychainBot()

    var tags: [String] = []

    func newTag() -> String {
        let tag = "a0.guardian.test.\(UUID().uuidString)"
        self.tags.append(tag)
        return tag
    }

    func clean(by tag: String? = nil) {
        if let tag = tag {
            remove(with: tag)
            guard let index = self.tags.firstIndex(of: tag) else { return }
            self.tags.remove(at: index)
        } else {
            self.tags.forEach { self.remove(with: $0) }
            self.tags.removeAll()
        }
    }

    private func remove(with tag: String) {
        let query: [String: Any] = [
            String(kSecAttrApplicationTag): tag
        ]
        let result = SecItemDelete(query as CFDictionary)
        if result != errSecSuccess {
            print("No key was removed!")
        }
    }

    func attributes(of key: SecKey?) -> [String: Any] {
        guard let key = key else { return [:] }
        return SecKeyCopyAttributes(key) as? [String: Any] ?? [:]
    }
}
