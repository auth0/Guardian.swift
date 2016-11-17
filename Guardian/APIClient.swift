// APIClient.swift
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

struct APIClient: API {

    let baseUrl: URL
    let session: URLSession
    
    init(baseUrl: URL, session: URLSession) {
        self.baseUrl = baseUrl
        self.session = session
    }

    func enroll(withTicket enrollmentTicket: String, identifier: String, name: String, notificationToken: String, publicKey: SecKey) -> DictionaryRequest {
        return DictionaryRequest {
            let url = self.baseUrl.appendingPathComponent("api/enroll")

            guard let publicKeyModulus = publicKey.modulus else {
                throw GuardianError.invalidPublicKey
            }

            let publicKeyModulusEncoded = publicKeyModulus.base64URLEncodedString()

            let payload: [String: Any] = [
                "identifier": identifier,
                "name": name,
                "push_credentials": [
                    "service": "APNS",
                    "token": notificationToken
                ],
                "public_key": [
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "e": "AQAB",
                    "n": publicKeyModulusEncoded,
                ]
            ]
            return Request(session: self.session, method: "POST", url: url, payload: payload, headers: ["Authorization": "Ticket id=\"\(enrollmentTicket)\""])
        }
    }

    func resolve(transaction transactionToken: String, withChallengeResponse challengeResponse: String) -> Request<Void> {
        let payload = [
            "challenge_response": challengeResponse
        ]
        let url = self.baseUrl.appendingPathComponent("api/resolve-transaction")
        return Request(session: self.session, method: "POST", url: url, payload: payload, headers: ["Authorization": "Bearer \(transactionToken)"])
    }

    func device(forEnrollmentId id: String, token: String) -> DeviceAPI {
        return DeviceAPIClient(baseUrl: baseUrl, session: session, id: id, token: token)
    }
}

///
/// Key data
///
private extension SecKey {

    /// Only works if the key is available in the keychain
    var keyData: Data? {
        let query: [String: Any] = [
            String(kSecClass)       : kSecClassKey,
            String(kSecAttrKeyType) : kSecAttrKeyTypeRSA,
            String(kSecValueRef)    : self,
            String(kSecReturnData)  : true
        ]
        var out: AnyObject?
        let result = SecItemCopyMatching(query as CFDictionary, &out)
        guard errSecSuccess == result, let data = out as? Data else {
            return nil
        }

        return data
    }

    var modulus: Data? {
        guard let key = self.keyData else {
            return nil
        }
        return key.splitIntoComponents()?.modulus
    }
}

///
/// Decoding lengths as octets
///
private extension NSInteger {

    init?(octetBytes: [CUnsignedChar], startIdx: inout NSInteger) {
        if octetBytes[startIdx] < 128 {
            // Short form
            self.init(octetBytes[startIdx])
            startIdx += 1
        } else {
            // Long form
            let octets = NSInteger(octetBytes[startIdx] as UInt8 - 128)

            if octets > octetBytes.count - startIdx {
                self.init(0)
                return nil
            }

            var result = UInt64(0)

            for j in 1...octets {
                result = (result << 8)
                result = result + UInt64(octetBytes[startIdx + j])
            }

            startIdx += 1 + octets
            self.init(result)
        }
    }
}

///
/// Manipulating data
///
private extension Data {

    func splitIntoComponents() -> (modulus: Data, exponent: Data)? {
        // Get the bytes from the keyData
        let pointer = (self as NSData).bytes.bindMemory(to: CUnsignedChar.self, capacity: self.count)
        let keyBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start:pointer, count:self.count / MemoryLayout<CUnsignedChar>.size))

        // Assumption is that the data is in DER encoding
        // If we can parse it, then return successfully
        var i: NSInteger = 0

        // First there should be an ASN.1 SEQUENCE
        if keyBytes[0] != 0x30 {
            return nil
        } else {
            i += 1
        }
        // Total length of the container
        if let _ = NSInteger(octetBytes: keyBytes, startIdx: &i) {
            // First component is the modulus
            if keyBytes[i] == 0x02 {
                i += 1
                if let modulusLength = NSInteger(octetBytes: keyBytes, startIdx: &i) {
                    let modulus = self.subdata(in: NSRange(location: i, length: modulusLength).toRange()!)
                    i += modulusLength

                    // Second should be the exponent
                    if keyBytes[i] == 0x02 {
                        i += 1
                        if let exponentLength = NSInteger(octetBytes: keyBytes, startIdx: &i) {
                            let exponent = self.subdata(in: NSRange(location: i, length: exponentLength).toRange()!)
                            i += exponentLength

                            return (modulus, exponent)
                        }
                    }
                }
            }
        }

        return nil
    }
}

public struct DictionaryRequest: Requestable {

    typealias T = [String: Any]
    typealias RequestBuilder = () throws -> Request<[String: Any]>

    private let buildRequest: RequestBuilder

    init(builder: @escaping RequestBuilder) {
        self.buildRequest = builder
    }

    /**
     Executes the request in a background thread

     - parameter callback: the termination callback, where the result is
     received
     */
    public func start(callback: @escaping (Result<[String: Any]>) -> ()) {
        do {
            let request = try buildRequest()
            request.start(callback: callback)
        } catch(let error) {
            callback(.failure(cause: error))
        }
    }
}
