// OneTimePassword.swift
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

struct TOTP {

    let hmac: A0HMAC
    let period: Int

    init?(withKey key: Data, period: Int, algorithm: String) {
        guard let hmac = A0HMAC(algorithm: algorithm, key: key) else {
            return nil
        }

        self.hmac = hmac
        self.period = period
    }

    func generate(digits: Int, counter: Int) -> String {
        var t = UInt64(counter / period).bigEndian
        let buffer = Data(bytes: &t, count: MemoryLayout<UInt64>.size);
        let digestData = hmac.sign(buffer)
        var offset: UInt8 = 0
        (digestData as NSData).getBytes(&offset, range: NSRange(location: hmac.digestLength - 1, length: MemoryLayout<UInt8>.size))
        offset &= 0x0f

        var binary: UInt32 = 0
        (digestData as NSData).getBytes(&binary, range: NSRange(location: Int(offset), length: MemoryLayout<UInt32>.size))
        var hash = UInt32(bigEndian: binary)
        hash &= 0x7fffffff

        hash = hash % UInt32(pow(10, Float(digits)))

        return String(format: "%0\(digits)d", Int(hash))
    }
}
