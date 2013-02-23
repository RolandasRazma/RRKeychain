//
//  RRKeychain.h
//
//  Created by Rolandas Razma on 23/02/2013.
//  Based partly on code by Buzz Andersen, Jonathan Wight, Jon Crosby, and Mike Malone.
//  Copyright 2013 Rolandas Razma. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person
//  obtaining a copy of this software and associated documentation
//  files (the "Software"), to deal in the Software without
//  restriction, including without limitation the rights to use,
//  copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following
//  conditions:
//
//  The above copyright notice and this permission notice shall be
//  included in all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
//  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
//  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
//  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
//  OTHER DEALINGS IN THE SOFTWARE.
//

#import <Foundation/Foundation.h>


NSString * const RRKeychainErrorDomain;


@interface RRKeychain : NSObject

+ (RRKeychain *)sharedKeychain;
- (NSArray *)accountsForService:(NSString *)service error:(NSError **)error;
- (NSString *)passwordForAccount:(NSString *)account andService:(NSString *)service error:(NSError **)error;
- (BOOL)setPassword:(NSString *)password forAccount:(NSString *)account andService:(NSString *)service error:(NSError **)error;
- (BOOL)removePasswordForAccount:(NSString *)account andService:(NSString *)service error:(NSError **)error;

@end
