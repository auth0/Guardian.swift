// Base32.swift
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

class Base32 {

    private static let paddingAdjustment: [Int] = [1, 1, 1, 2, 3, 3, 4, 5]
    private static let __: UInt8 = 255
    private static let defaultDecodingTable: [UInt8] = [
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x00 - 0x0F
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x10 - 0x1F
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x20 - 0x2F
        __,__,26,27, 28,29,30,31, __,__,__,__, __, 0,__,__,  // 0x30 - 0x3F
        __, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,  // 0x40 - 0x4F
        15,16,17,18, 19,20,21,22, 23,24,25,__, __,__,__,__,  // 0x50 - 0x5F
        __, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,  // 0x60 - 0x6F
        15,16,17,18, 19,20,21,22, 23,24,25,__, __,__,__,__,  // 0x70 - 0x7F
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x80 - 0x8F
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x90 - 0x9F
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xA0 - 0xAF
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xB0 - 0xBF
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xC0 - 0xCF
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xD0 - 0xDF
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xE0 - 0xEF
        __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xF0 - 0xFF
    ]

    static func decode(string: String, decodingTable: [UInt8] = defaultDecodingTable) -> Data? {
        let encoding = string.replacingOccurrences(of: "=", with: "")
        guard let encodedData = encoding.data(using: .ascii) else {
            return nil
        }
        let encodedLength = encodedData.count
        let encodedBytes = [UInt8](encodedData)
        let encodedBlocks = Int( ceil( Double(encodedLength) / 8.0 ) )
        let expectedDataLength = encodedBlocks * 5
        var decodedBytes = [UInt8](repeating: 0, count: expectedDataLength)
        var decodedBaseIndex = 0
        var encodedBlock: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        var encodedBlockIndex = 0

        for encodedBaseIndex in 0..<encodedLength {
            let currentByte = encodedBytes[encodedBaseIndex]
            let currentValue = decodingTable[Int(currentByte)]
            if currentValue == __ {
                return nil
            }

            encodedBlock[encodedBlockIndex] = currentValue
            encodedBlockIndex += 1
            if encodedBlockIndex == 8 || encodedBaseIndex == encodedLength-1 {
                let encodedByte8: UInt8 = encodedBlockIndex > 7 ? encodedBlock[7] : 0
                let encodedByte7: UInt8 = encodedBlockIndex > 6 ? encodedBlock[6] : 0
                let encodedByte6: UInt8 = encodedBlockIndex > 5 ? encodedBlock[5] : 0
                let encodedByte5: UInt8 = encodedBlockIndex > 4 ? encodedBlock[4] : 0
                let encodedByte4: UInt8 = encodedBlockIndex > 3 ? encodedBlock[3] : 0
                let encodedByte3: UInt8 = encodedBlockIndex > 2 ? encodedBlock[2] : 0
                let encodedByte2: UInt8 = encodedBlockIndex > 1 ? encodedBlock[1] : 0
                let encodedByte1: UInt8 = encodedBlock[0]

                decodedBytes[decodedBaseIndex]   = ((encodedByte1 << 3) & 0xF8) | ((encodedByte2 >> 2) & 0x07)
                decodedBytes[decodedBaseIndex+1] = ((encodedByte2 << 6) & 0xC0) | ((encodedByte3 << 1) & 0x3E) | ((encodedByte4 >> 4) & 0x01)
                decodedBytes[decodedBaseIndex+2] = ((encodedByte4 << 4) & 0xF0) | ((encodedByte5 >> 1) & 0x0F)
                decodedBytes[decodedBaseIndex+3] = ((encodedByte5 << 7) & 0x80) | ((encodedByte6 << 2) & 0x7C) | ((encodedByte7 >> 3) & 0x03)
                decodedBytes[decodedBaseIndex+4] = ((encodedByte7 << 5) & 0xE0) | (encodedByte8 & 0x1F)

                decodedBaseIndex += paddingAdjustment[encodedBlockIndex-1]
                encodedBlockIndex = 0
            }
        }

        return Data(bytes: UnsafePointer<UInt8>(decodedBytes), count: decodedBaseIndex)
    }
}
