// AOHMAC.swift
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
import CommonCrypto

struct A0HMAC {
    private let digestLength: Int
    private let algorithm: CCHmacAlgorithm
    private let key: Data
    
    init?(algorithm: String, key: Data) {
        let alg = algorithm.lowercased()
        switch alg {
        case "sha1":
            self.algorithm = CCHmacAlgorithm(kCCHmacAlgSHA1)
            digestLength = Int(CC_SHA1_DIGEST_LENGTH)
        case "sha256":
            self.algorithm = CCHmacAlgorithm(kCCHmacAlgSHA256)
            digestLength = Int(CC_SHA256_DIGEST_LENGTH)
        case "sha512":
            self.algorithm = CCHmacAlgorithm(kCCHmacAlgSHA512)
            digestLength = Int(CC_SHA512_DIGEST_LENGTH)
        default:
            return nil
        }
        self.key = key
    }
    
    func sign(_ data: Data) -> Data {
        var hashBytes = [UInt8](repeating: 0, count: digestLength)
        key.withUnsafeBytes { key in
            data.withUnsafeBytes { data in
                CCHmac(algorithm, key.baseAddress, key.count, data.baseAddress, data.count, &hashBytes)
            }
        }
        return Data(hashBytes)
    }
}
