// NSData+Base32.swift
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

extension NSData {

    convenience init?(fromBase32String string: String) {
        guard let data = Base32Decode(string) else {
            return nil
        }
        self.init(data: data)
    }
}

private let __: UInt8 = 255
private let decodingTable: [UInt8] = [
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

private func Base32Decode(data: String) -> NSData? {
    return Base32Decode(data: data, decodingTable: decodingTable)
}

private func Base32Decode(data data: String, decodingTable: [UInt8]) -> NSData? {
    let paddingAdjustment: [Int] = [0,1,1,1,2,3,3,4]
    let encoding = data.stringByReplacingOccurrencesOfString("=", withString: "")
    guard let encodedData = encoding.dataUsingEncoding(NSASCIIStringEncoding) else {
        return nil
    }
    let encodedBytes = UnsafePointer<UInt8>(encodedData.bytes)
    let encodedLength = encodedData.length
    var encodedBlocks = (encodedLength * 5) / 40
    if encodedLength % 8 != 0 {
        encodedBlocks += 1
    }
    let expectedDataLength = encodedBlocks * 5

    let decodedBytes = UnsafeMutablePointer<UInt8>.alloc(expectedDataLength)

    var encodedByte1: UInt8, encodedByte2: UInt8, encodedByte3: UInt8, encodedByte4: UInt8, encodedByte5: UInt8, encodedByte6: UInt8, encodedByte7: UInt8, encodedByte8: UInt8
    var encodedBytesToProcess = encodedLength
    var encodedBaseIndex = 0
    var decodedBaseIndex = 0
    var encodedBlock: [UInt8] = [0,0,0,0,0,0,0,0]
    var encodedBlockIndex = 0
    var c: UInt8
    var error = false
    while encodedBytesToProcess >= 1 {
        encodedBytesToProcess -= 1
        c = encodedBytes[encodedBaseIndex]
        encodedBaseIndex += 1

        if c == UInt8("=") {
            break // padding...
        }

        c = decodingTable[Int(c)]
        if c == __ {
            error = true
            break
        }

        encodedBlock[encodedBlockIndex] = c
        encodedBlockIndex += 1
        if encodedBlockIndex == 8 {
            encodedByte1 = encodedBlock[0]
            encodedByte2 = encodedBlock[1]
            encodedByte3 = encodedBlock[2]
            encodedByte4 = encodedBlock[3]
            encodedByte5 = encodedBlock[4]
            encodedByte6 = encodedBlock[5]
            encodedByte7 = encodedBlock[6]
            encodedByte8 = encodedBlock[7]
            decodedBytes[decodedBaseIndex]   = ((encodedByte1 << 3) & 0xF8) | ((encodedByte2 >> 2) & 0x07)
            decodedBytes[decodedBaseIndex+1] = ((encodedByte2 << 6) & 0xC0) | ((encodedByte3 << 1) & 0x3E) | ((encodedByte4 >> 4) & 0x01)
            decodedBytes[decodedBaseIndex+2] = ((encodedByte4 << 4) & 0xF0) | ((encodedByte5 >> 1) & 0x0F)
            decodedBytes[decodedBaseIndex+3] = ((encodedByte5 << 7) & 0x80) | ((encodedByte6 << 2) & 0x7C) | ((encodedByte7 >> 3) & 0x03)
            decodedBytes[decodedBaseIndex+4] = ((encodedByte7 << 5) & 0xE0) | (encodedByte8 & 0x1F)
            decodedBaseIndex += 5
            encodedBlockIndex = 0
        }
    }
    encodedByte7 = 0
    encodedByte6 = 0
    encodedByte5 = 0
    encodedByte4 = 0
    encodedByte3 = 0
    encodedByte2 = 0
    switch encodedBlockIndex {
    case 7:
        encodedByte7 = encodedBlock[6]
        fallthrough
    case 6:
        encodedByte6 = encodedBlock[5]
        fallthrough
    case 5:
        encodedByte5 = encodedBlock[4]
        fallthrough
    case 4:
        encodedByte4 = encodedBlock[3]
        fallthrough
    case 3:
        encodedByte3 = encodedBlock[2]
        fallthrough
    case 2:
        encodedByte2 = encodedBlock[1]
        fallthrough
    case 1:
        encodedByte1 = encodedBlock[0]
        decodedBytes[decodedBaseIndex]   = ((encodedByte1 << 3) & 0xF8) | ((encodedByte2 >> 2) & 0x07)
        decodedBytes[decodedBaseIndex+1] = ((encodedByte2 << 6) & 0xC0) | ((encodedByte3 << 1) & 0x3E) | ((encodedByte4 >> 4) & 0x01)
        decodedBytes[decodedBaseIndex+2] = ((encodedByte4 << 4) & 0xF0) | ((encodedByte5 >> 1) & 0x0F)
        decodedBytes[decodedBaseIndex+3] = ((encodedByte5 << 7) & 0x80) | ((encodedByte6 << 2) & 0x7C) | ((encodedByte7 >> 3) & 0x03)
        decodedBytes[decodedBaseIndex+4] = ((encodedByte7 << 5) & 0xE0)
    default:
        break
    }
    var data: NSData? = nil
    if !error {
        decodedBaseIndex += paddingAdjustment[encodedBlockIndex]
        data = NSData(bytes: decodedBytes, length: decodedBaseIndex)
    }
    decodedBytes.destroy()
    return data
}
