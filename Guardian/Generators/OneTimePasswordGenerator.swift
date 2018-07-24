// OneTimePasswordGenerator.swift
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

public protocol TOTP {
    func new(time: TimeInterval, period: Int) -> String
}

extension TOTP {
    public func new(time: TimeInterval = Date().timeIntervalSince1970, period: Int = 30) -> String {
        return self.new(time: time, period: period)
    }
}

public protocol HOTP {
    func new(counter: Int) -> String
}

public func totp(base32Secret: String, algorithm: String, digits: Int = 6) throws -> TOTP {
    guard let secret = Base32.decode(string: base32Secret) else { throw GuardianError.invalidBase32Secret }
    return try totp(secret: secret, algorithm: algorithm, digits: digits)
}

public func totp(secret: Data, algorithm: String, digits: Int = 6) throws -> TOTP {
    return try OneTimePasswordGenerator(secret: secret, algorithm: algorithm, digits: digits)
}

public func hotp(secret: Data, algorithm: String, digits: Int = 6) throws -> HOTP {
    return try OneTimePasswordGenerator(secret: secret, algorithm: algorithm, digits: digits)
}

struct OneTimePasswordGenerator: TOTP, HOTP {
    let digits: Int
    let hmac: A0HMAC

    init(secret: Data, algorithm: String, digits: Int) throws {
        guard let hmac = A0HMAC(algorithm: algorithm, key: secret) else {
            throw GuardianError.invalidOTPAlgorithm
        }
        self.hmac = hmac
        self.digits = digits
    }

    func new(counter: Int) -> String {
        var c = UInt64(counter).bigEndian
        let buffer = Data(bytes: &c, count: MemoryLayout<UInt64>.size);
        let digestData = hmac.sign(buffer)
        let hash = digestData.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UInt32 in
            let last = bytes.advanced(by: hmac.digestLength - 1)
            let offset = last.pointee & 0x0f
            let start = bytes.advanced(by: Int(offset))
            let value = start.withMemoryRebound(to: UInt32.self, capacity: 1) { $0 }
            var hash = UInt32(bigEndian: value.pointee)
            hash &= 0x7fffffff
            hash = hash % UInt32(pow(10, Float(digits)))
            return hash
        }

        return String(format: "%0\(digits)d", Int(hash))
    }

    func new(time: TimeInterval, period: Int) -> String {
        let steps = time / Double(period)
        return self.new(counter: Int(steps))
    }
}
