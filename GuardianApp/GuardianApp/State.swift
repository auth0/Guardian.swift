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
    /// Looked up in the keychain when the state is decoded, never encoded.
    private let key: KeychainRSAPrivateKey

    private enum CodingKeys: String, CodingKey {
        case identifier, localIdentifier, keyTag, otp, userId
    }

    /// The vendor identifier the SDK uses as an enrollment's local identifier.
    /// It is nil after a restart until the device is first unlocked.
    static var currentLocalIdentifier: String? {
        return UIDevice.current.identifierForVendor?.uuidString
    }

    init(identifier: String, localIdentifier: String, signingKey: KeychainRSAPrivateKey, otp: OTPParameters?, userId: String) {
        self.identifier = identifier
        self.localIdentifier = localIdentifier
        self.keyTag = signingKey.tag
        self.key = signingKey
        self.otp = otp
        self.userId = userId
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        identifier = try container.decode(String.self, forKey: .identifier)
        localIdentifier = try container.decode(String.self, forKey: .localIdentifier)
        keyTag = try container.decode(String.self, forKey: .keyTag)
        otp = try container.decodeIfPresent(OTPParameters.self, forKey: .otp)
        userId = try container.decode(String.self, forKey: .userId)
        // Fails, and so drops the state, if the signing key is gone.
        key = try KeychainRSAPrivateKey(tag: keyTag)
    }

    func save() throws {
        let encoder = JSONEncoder()
        let data = try encoder.encode(self)
        try Keychain.set(data, forKey: self.localIdentifier)
    }

    /// Deletes the stored enrollment and its device signing key.
    static func delete(by identifier: String? = currentLocalIdentifier) {
        guard let identifier = identifier else { return }
        if let state = load(by: identifier) {
            deleteSigningKey(withTag: state.keyTag)
        }
        Keychain.delete(forKey: identifier)
    }

    /// Deletes a device signing key created with KeychainRSAPrivateKey.new(with:).
    /// The SDK has no API for this, so remove the keychain item directly.
    static func deleteSigningKey(withTag tag: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8)
        ]
        SecItemDelete(query as CFDictionary)
    }

    static func load(by identifier: String? = currentLocalIdentifier) -> GuardianState? {
        guard let identifier = identifier else { return nil }
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
        return key
    }
}
