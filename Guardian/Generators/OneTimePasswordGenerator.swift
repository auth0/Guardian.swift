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
    func stringCode(time: TimeInterval, formatter: NumberFormatter?) -> String
    func code(time: TimeInterval) -> Int
}

public extension TOTP {
    public func stringCode(time: TimeInterval = Date().timeIntervalSince1970, formatter: NumberFormatter? = nil) -> String {
        return self.stringCode(time: time, formatter: formatter)
    }

    public func code() -> Int {
        return self.code(time: Date().timeIntervalSince1970)
    }
}

public protocol HOTP {
    func stringCode(counter: Int, formatter: NumberFormatter?) -> String
    func code(counter: Int) -> Int
}

public func totp(base32Secret: String, algorithm: HMACAlgorithm, digits: Int = 6, period: Int = 30) throws -> TOTP {
    return try totp(parameters: OTPParameters(base32Secret: base32Secret, algorithm: algorithm, digits: digits, period: period))
}

public func totp(parameters: OTPParameters) throws -> TOTP {
    return try OneTimePasswordGenerator(parameters: parameters)
}

public func hotp(base32Secret: String, algorithm: HMACAlgorithm, digits: Int = 6) throws -> HOTP {
    return try hotp(parameters: OTPParameters(base32Secret: base32Secret, algorithm: algorithm, digits: digits))
}

public func hotp(parameters: OTPParameters) throws -> HOTP {
    return try OneTimePasswordGenerator(parameters: parameters)
}

public enum HMACAlgorithm: String, Codable {
    case sha1
    case sha256
    case sha512

    func hmac(secret: Data) -> A0HMAC {
        return A0HMAC(algorithm: self.rawValue, key: secret)!
    }
}

struct OneTimePasswordGenerator: TOTP, HOTP {
    let parameters: OTPParameters
    let hmac: A0HMAC

    init(parameters: OTPParameters) throws {
        self.parameters = parameters
        guard let secret = Base32.decode(string: parameters.base32Secret) else { throw GuardianError(code: .invalidOTPSecret) }
        self.hmac = parameters.algorithm.hmac(secret: secret)
    }

    func code(counter: Int) -> Int {
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
            hash = hash % UInt32(pow(10, Float(self.parameters.digits)))
            return hash
        }

        return Int(hash)
    }

    func stringCode(counter: Int, formatter: NumberFormatter? = nil) -> String {
        let code = self.code(counter: counter)
        return format(code: code, digits: self.parameters.digits, formatter: formatter)
    }

    func code(time: TimeInterval) -> Int {
        let steps = timeSteps(from: time, period: self.parameters.period)
        return self.code(counter: steps)
    }

    func stringCode(time: TimeInterval, formatter: NumberFormatter? = nil) -> String {
        let steps = timeSteps(from: time, period: self.parameters.period)
        let code = self.code(counter: steps)
        return format(code: code, digits: self.parameters.digits, formatter: formatter)
    }

    private func timeSteps(from time: TimeInterval, period: Int) -> Int {
        return Int(time / Double(self.parameters.period))
    }

    private func format(code: Int, digits: Int, formatter: NumberFormatter?) -> String {
        let defaultFormatted = String(format: "%0\(digits)d", code)
        guard let formatter = formatter else { return defaultFormatted }
        return formatter.string(from: NSNumber(value: code)) ?? defaultFormatted
    }
}
