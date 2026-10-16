// State.swift
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

import UIKit
import Guardian

struct GuardianState: Codable {

    let identifier: String
    let localIdentifier: String
    let keyTag: String
    let otp: OTPParameters?
    let userId: String

    func save() throws {
        let encoder = JSONEncoder()
        let data = try encoder.encode(self)
        try Keychain.set(data, forKey: self.localIdentifier)
    }

    static func delete(by identifier: String = UIDevice.current.identifierForVendor!.uuidString) {
        Keychain.delete(forKey: identifier)
    }

    static func load(by identifier: String = UIDevice.current.identifierForVendor!.uuidString) -> GuardianState? {
        let decoder = JSONDecoder()
        guard let data = Keychain.data(forKey: identifier) else { return nil }
        guard let state = try? decoder.decode(GuardianState.self, from: data) else { return nil }
        guard state.localIdentifier == identifier else { return nil }
        return state
    }
}

/// Minimal generic-password store for the sample's enrollment state, so the
/// sample has no dependencies beyond the Guardian SDK itself.
private enum Keychain {

    private static let service = Bundle.main.bundleIdentifier ?? "com.auth0.guardian.sample"

    private static func query(forKey key: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
    }

    static func set(_ data: Data, forKey key: String) throws {
        delete(forKey: key)
        var attributes = query(forKey: key)
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    static func data(forKey key: String) -> Data? {
        var lookup = query(forKey: key)
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        guard SecItemCopyMatching(lookup as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    static func delete(forKey key: String) {
        SecItemDelete(query(forKey: key) as CFDictionary)
    }
}

extension GuardianState: AuthenticationDevice {
    var signingKey: SigningKey {
        return try! KeychainRSAPrivateKey(tag: self.keyTag)
    }
}
