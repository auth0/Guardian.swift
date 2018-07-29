// ASNPublicKeyDecodable.swift
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

public struct PublicKeyAttributes {
    public let modulus: Data
    public let exponent: Data
}

public protocol ASNPublicKeyDecodable: PublicKeyDataConvertible {
    var attributes: PublicKeyAttributes? { get }
}

extension ASNPublicKeyDecodable {

    public var attributes: PublicKeyAttributes? {
        let asn = { (bytes: UnsafePointer<UInt8>) -> PublicKeyAttributes? in
            guard bytes.pointee == 0x30 else { return nil }
            let (modulusBytes, totalLength) = self.length(from: bytes + 1)
            guard totalLength > 0, let (exponentBytes, modulus) = self.data(from: modulusBytes) else { return nil }
            guard let (end, exponent) = self.data(from: exponentBytes) else { return nil }
            guard abs(end.distance(to: modulusBytes)) == totalLength else { return nil }
            return PublicKeyAttributes(modulus: modulus, exponent: exponent)
        }
        return self.data?.withUnsafeBytes(asn)
    }

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
}

extension VerificationKey where Self: ASNPublicKeyDecodable {

    public var jwk: RSAPublicJWK? {
        guard let attributes = self.attributes else { return nil }
        return RSAPublicJWK(modulus: attributes.modulus.base64URLEncodedString(), exponent: attributes.exponent.base64URLEncodedString())
    }
}
