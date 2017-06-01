// RSAKeyPair.swift
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

import Foundation

/**
 A RSA key pair.
 
 Contains the public and private keys of an RSA key pair.
 
 Includes static methods for the creation of a new key pair, and to obtain a
 public or private key from a tag.
 */
public class RSAKeyPair {

    /**
     The public key
     */
    public let publicKey: RSAPublicKey

    /**
     The private key
     */
    public let privateKey: RSAPrivateKey

    init(publicKey: RSAPublicKey, privateKey: RSAPrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    public convenience init(publicKeyTag: String, privateKeyTag: String) {
        self.init(publicKey: RSAKeyPair.publicKey(withTag: publicKeyTag),
                  privateKey: RSAKeyPair.privateKey(withTag: privateKeyTag))
    }

    /**
     Creates a new pair of RSA keys using the provided tags.
     
     The keys are automatically saved in the keychain, and we'll later access 
     them by tag, so you must use appropriate unique identifiers for every pair
     of keys you create.
     
     You must also use keys of at least 2048 bits.
     
     - parameter usingPublicTag: the tag for the public key
     - parameter privateTag:     the tag for the private key
     - parameter keySize:        the size of the keys, in bits
     
     - returns: an instance of RSAKeyPair, or nil if the keys couldn't be 
                generated
     */
    public static func new(usingPublicTag publicTag: String, privateTag: String, keySize: Int = 2048) -> RSAKeyPair? {
        var query: [String: Any] = [
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrKeySizeInBits) : keySize,
        ]
        query[String(kSecPrivateKeyAttrs)] = [
            String(kSecAttrIsPermanent)    : true,
            String(kSecAttrApplicationTag) : privateTag
        ]
        query[String(kSecPublicKeyAttrs)] = [
            String(kSecAttrIsPermanent)    : true,
            String(kSecAttrApplicationTag) : publicTag
        ]

        var privateKey: SecKey?
        var publicKey: SecKey?

        let status = SecKeyGeneratePair(query as CFDictionary, &publicKey, &privateKey)
        guard status == errSecSuccess else { return nil }
        return RSAKeyPair(publicKeyTag: publicTag, privateKeyTag: privateTag)
    }

    /**
     Returns a public key using the tag.
     
     - parameter withTag: the tag of the key
     
     - returns: an instance of RSAPublicKey
     
     - important: an instance is always returned, this method doesn't actually
                  verify that the key is present in the keychain and that the
                  type of the key is appropriate.
     */
    public static func publicKey(withTag tag: String) -> RSAPublicKey {
        return ASNPublicKey(tag: tag)
    }

    /**
     Returns a private key using the tag.

     - parameter withTag: the tag of the key

     - returns: an instance of RSAPrivateKey

     - important: an instance is always returned, this method doesn't actually
                  verify that the key is present in the keychain and that the
                  type of the key is appropriate.
     */
    public static func privateKey(withTag tag: String) -> RSAPrivateKey {
        return SimpleRSAPrivateKey(tag: tag)
    }
}

/**
 A protocol that represents an RSA private key.
 
 The key is saved in the keychain under certain tag, so it's enough if you only
 store the tag. You can later use `RSAKeyPair.privateKey(withTag:)` to obtain it
 again, assuming you used unique tags.
 */
public protocol RSAPrivateKey: KeychainRSAKey {
}

/**
 A protocol that represents an RSA public key.
 
 The key is saved in the keychain under certain tag, so it's enough if you only 
 store the tag. You can later use `RSAKeyPair.publicKey(withTag:)` to obtain it
 again, assuming you used unique tags.
 */
public protocol RSAPublicKey: KeychainRSAKey, JWKConvertable {
}

/**
 A protocol that represents a key saved in the keychain under certain tag
 */
public protocol KeychainRSAKey {

    /**
     The tag of the key
     */
    var tag: String { get }
}

/**
 A protocol that represents a key that can be converted to JWK format
 */
public protocol JWKConvertable {

    /**
     The binary data of the key.

     The format of the data depends on the type of key.
     */
    var data: Data? { get }

    /**
     Key as JSON Web Key format (JWK).

     If key is invalid it will return nil.
    */
    var jwk: [String: Any]? { get }
}

extension JWKConvertable {
    private func length(from bytes: UnsafePointer<UInt8>) -> (UnsafePointer<UInt8>, Int) {
        guard bytes.pointee > 0x7f else {
            return (bytes + 1, Int(bytes.pointee))
        }

        let count = Int(bytes.pointee & 0x7f)
        let length = (1...count).reduce(0) {
            ($0 << 8) + Int(bytes[$1])
        }
        let pointer = bytes + (1 + count)
        return (pointer, length)
    }

    private func data(from bytes: UnsafePointer<UInt8>) -> (UnsafePointer<UInt8>, Data)? {
        guard bytes.pointee == 0x02 else { return nil }
        let (valueBytes, valueLength) = length(from: bytes + 1)
        let data = Data(bytes: valueBytes, count: valueLength)
        let pointer = valueBytes + valueLength
        return (pointer, data)
    }

    var jwk: [String : Any]? {
        let asn = { (bytes: UnsafePointer<UInt8>) -> (Data, Data)? in
            guard bytes.pointee == 0x30 else { return nil }
            let (modulusBytes, totalLength) = self.length(from: bytes + 1)
            guard totalLength > 0, let (exponentBytes, modulus) = self.data(from: modulusBytes) else { return nil }
            guard let (end, exponent) = self.data(from: exponentBytes) else { return nil }
            guard abs(end.distance(to: modulusBytes)) == totalLength else { return nil }
            return (modulus, exponent)
        }
        guard let (modulus, exponent) = self.data?.withUnsafeBytes(asn) else { return nil }
        return [
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "e": exponent.base64URLEncodedString(),
            "n": modulus.base64URLEncodedString(),
        ]
    }
}

public extension KeychainRSAKey {

    /**
     Returns the `SecKey` instance
     
     - important: This method might return nil if a key with this tag is not 
                  present in the keychain or if the type of the key is not 
                  appropriate.
     */
    var ref: SecKey? {
        let query: [String: Any] = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : self.tag,
            String(kSecReturnRef)          : true
        ]
        var out: AnyObject?
        let result = SecItemCopyMatching(query as CFDictionary, &out)
        guard errSecSuccess == result else {
            return nil
        }

        return (out as! SecKey)
    }
}

struct SimpleRSAPrivateKey: RSAPrivateKey {
    let tag: String
}

struct ASNPublicKey: RSAPublicKey {
    let tag: String
    var data: Data? {
        let query: [String: Any] = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : self.tag,
            String(kSecReturnData)         : true
        ]
        var out: AnyObject?
        let result = SecItemCopyMatching(query as CFDictionary, &out)
        guard errSecSuccess == result else {
            return nil
        }
        return out as? Data
    }
}

