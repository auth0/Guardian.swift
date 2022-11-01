// A0RSA.m
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

#import <A0RSA.h>
#import <CommonCrypto/CommonCrypto.h>

@interface A0RSA ()
@property (readonly, nonatomic) SecKeyRef key;
@end

@implementation A0RSA

- (nullable instancetype)initWithKey: (SecKeyRef)key {
    self = [super init];
    if (self) {
        _key = key;
    }
    return self;
}

- (NSData *)sign_ios_15_or_earlier:(NSData *)plainData {
    size_t signedHashBytesSize = SecKeyGetBlockSize(self.key);
    uint8_t signedHashBytes[signedHashBytesSize];
    memset(signedHashBytes, 0x0, signedHashBytesSize);

    OSStatus result = SecKeyRawSign(self.key,
                                    kSecPaddingPKCS1SHA256,
                                    plainData.bytes,
                                    plainData.length,
                                    signedHashBytes,
                                    &signedHashBytesSize);

    NSData* signedHash = nil;
    if (result == errSecSuccess) {
        signedHash = [NSData dataWithBytes:signedHashBytes
                                    length:(NSUInteger)signedHashBytesSize];
    }

    return signedHash;
}

- (NSData *)sign_ios_16_or_later:(NSData *)plainData {
    
    CFDataRef dataToSign = CFDataCreate(NULL, plainData.bytes, plainData.length);
    CFDataRef signature = SecKeyCreateSignature(self.key,
                                                kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
                                                dataToSign,
                                                nil);
    CFRelease(dataToSign);
    if (!signature) {
        return nil;
    }
    
    const UInt8* signedHashBytes = CFDataGetBytePtr(signature);
    const CFIndex length  = CFDataGetLength(signature);
    
    return [NSData dataWithBytes:signedHashBytes
                          length:(NSUInteger)length];
}

- (NSData *)sign:(NSData *)plainData {
    if (@available(iOS 16, *)) {
        // iOS 16 or later
        return [self sign_ios_16_or_later: plainData];
    }

    // iOS 15 or earlier
    return [self sign_ios_15_or_earlier: plainData];
}

- (Boolean)verify:(NSData *)plainData signature:(NSData *)signature {
    
    if (@available(iOS 16, *)) {
        // iOS 16 or later
        CFDataRef plainDataRef = CFDataCreate(NULL, plainData.bytes, plainData.length);
        CFDataRef signatureRef = CFDataCreate(NULL, signature.bytes, signature.length);

        Boolean verified = SecKeyVerifySignature(self.key,
                                                 kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
                                                 plainDataRef,
                                                 signatureRef,
                                                 nil);
        CFRelease(plainDataRef);
        CFRelease(signatureRef);
        
        return verified;
    }
    
    // iOS 15 or earlier
    OSStatus result = SecKeyRawVerify(self.key,
                                      kSecPaddingPKCS1SHA256,
                                      plainData.bytes,
                                      plainData.length,
                                      signature.bytes,
                                      signature.length);
    return result == errSecSuccess;
}

@end
