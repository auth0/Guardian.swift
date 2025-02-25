// ModelsSpec.swift
//
// Copyright (c) 2025 Auth0 (http://auth0.com)
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

public enum Json: Equatable, Codable {
    case string(String)
    case number(Double)
    case object([String:Json])
    case array([Json])
    case bool(Bool)
    case null
    
    public func encode(to encoder: Encoder) throws {

        var container = encoder.singleValueContainer()

        switch self {
        case let .array(array):
            try container.encode(array)
        case let .object(object):
            try container.encode(object)
        case let .string(string):
            try container.encode(string)
        case let .number(number):
            try container.encode(number)
        case let .bool(bool):
            try container.encode(bool)
        case .null:
            try container.encodeNil()
        }
    }

    public init(from decoder: Decoder) throws {

        let container = try decoder.singleValueContainer()

        if let object = try? container.decode([String: Json].self) {
            self = .object(object)
        } else if let array = try? container.decode([Json].self) {
            self = .array(array)
        } else if let string = try? container.decode(String.self) {
            self = .string(string)
        } else if let bool = try? container.decode(Bool.self) {
            self = .bool(bool)
        } else if let number = try? container.decode(Double.self) {
            self = .number(number)
        } else if container.decodeNil() {
            self = .null
        } else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid JSON value.")
            )
        }
    }
    
    /// Return the string value if this is a `.string`, otherwise `nil`
    public var stringValue: String? {
        if case .string(let value) = self {
            return value
        }
        return nil
    }
    
    /// Return the double value if this is a `.number`, otherwise `nil`
    public var doubleValue: Double? {
        if case .number(let value) = self {
            return value
        }
        return nil
    }
    
    /// Return the bool value if this is a `.bool`, otherwise `nil`
    public var boolValue: Bool? {
        if case .bool(let value) = self {
            return value
        }
        return nil
    }
    
    /// Return the object value if this is an `.object`, otherwise `nil`
    public var objectValue: [String: Json]? {
        if case .object(let value) = self {
            return value
        }
        return nil
    }
    
    /// Return the array value if this is an `.array`, otherwise `nil`
    public var arrayValue: [Json]? {
        if case .array(let value) = self {
            return value
        }
        return nil
    }
    
    /// Return `true` iff this is `.null`
    public var isNull: Bool {
        if case .null = self {
            return true
        }
        return false
    }
    
    /// If this is an `.array`, return item at index
    ///
    /// If this is not an `.array` or the index is out of bounds, returns `nil`.
    public subscript(index: Int) -> Json? {
        if case .array(let arr) = self, arr.indices.contains(index) {
            return arr[index]
        }
        return nil
    }
    
    /// If this is an `.object`, return item at key
    public subscript(key: String) -> Json? {
        if case .object(let dict) = self {
            return dict[key]
        }
        return nil
    }
}
