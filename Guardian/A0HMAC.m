// A0HMAC.m
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

#import <A0HMAC.h>
#import <CommonCrypto/CommonHMAC.h>

@interface A0HMAC ()
@property (readonly, nonatomic) CCHmacAlgorithm algorithm;
@property (readonly, strong, nonatomic) NSData *key;
@end

@implementation A0HMAC

- (instancetype)initWithAlgorithm:(NSString *)algorithm key:(NSData *)key {
    self = [super init];
    if (self) {
        const NSString * alg = algorithm.lowercaseString;
        if ([@"sha1"  isEqual: alg]) {
            _algorithm = kCCHmacAlgSHA1;
            _digestLength = CC_SHA1_DIGEST_LENGTH;
        } else if ([@"sha256"  isEqual: alg]) {
            _algorithm = kCCHmacAlgSHA256;
            _digestLength = CC_SHA256_DIGEST_LENGTH;
        } else if ([@"sha512"  isEqual: alg]) {
            _algorithm = kCCHmacAlgSHA512;
            _digestLength = CC_SHA512_DIGEST_LENGTH;
        } else {
            return nil;
        }
        _key = key;
    }
    return self;
}

- (NSData *)sign:(NSData *)data {
    uint8_t hashBytes[self.digestLength];
    memset(hashBytes, 0x0, self.digestLength);
    CCHmac(self.algorithm, self.key.bytes, self.key.length, data.bytes, data.length, hashBytes);
    NSData *hash = [NSData dataWithBytes:hashBytes length:self.digestLength];
    return hash;
}

@end
