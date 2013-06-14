//
//  RRKeychain.m
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

#import "RRKeychain.h"
#import <Security/Security.h>


NSString * const RRKeychainErrorDomain = @"RRKeychainErrorDomain";


@implementation RRKeychain


#pragma mark -
#pragma mark RRKeychain


+ (RRKeychain *)sharedKeychain {
    static RRKeychain *_sharedKeychain;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _sharedKeychain = [[RRKeychain alloc] init];
    });
    return _sharedKeychain;
}


- (NSError *)errorForOSStatus:(OSStatus)status {
    
    switch ( status ) {
        case errSecSuccess:
            return nil;
        case errSecUnimplemented:
            return [NSError errorWithDomain:RRKeychainErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey:@"Function or operation not implemented."}];
        case errSecParam:
            return [NSError errorWithDomain:RRKeychainErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey:@"One or more parameters passed to a function where not valid."}];
        case errSecAllocate:
            return [NSError errorWithDomain:RRKeychainErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey:@"Failed to allocate memory."}];
        case errSecNotAvailable:
            return [NSError errorWithDomain:RRKeychainErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey:@"No keychain is available. You may need to restart your computer."}];
        case errSecDuplicateItem:
            return [NSError errorWithDomain:RRKeychainErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey:@"The specified item already exists in the keychain."}];
        case errSecItemNotFound:
            return [NSError errorWithDomain:RRKeychainErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey:@"The specified item could not be found in the keychain."}];
        case errSecInteractionNotAllowed:
            return [NSError errorWithDomain:RRKeychainErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey:@"User interaction is not allowed."}];
        case errSecDecode:
            return [NSError errorWithDomain:RRKeychainErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey:@"Unable to decode the provided data."}];
        case errSecAuthFailed:
            return [NSError errorWithDomain:RRKeychainErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey:@"The user name or passphrase you entered is not correct."}];
        default:
            return [NSError errorWithDomain:RRKeychainErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey:@"Unknown error"}];
    }
    
}


- (NSArray *)accountsForService:(NSString *)service error:(NSError * __autoreleasing *)error {
    
    // nil error
    if( error != NULL ) *error = nil;
    
    // create query
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(query, kSecReturnAttributes,   kCFBooleanTrue);
    CFDictionaryAddValue(query, kSecMatchLimit,         kSecMatchLimitAll);
    CFDictionaryAddValue(query, kSecClass,              kSecClassGenericPassword);
    CFDictionaryAddValue(query, kSecAttrService,        (__bridge const void *)(service));
    
    // perform query
    CFArrayRef result = nil;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&result);
    CFRelease(query);
    
    // did we got error?
    if( status != errSecSuccess ) {
        if ( error != NULL ) {
            *error = [self errorForOSStatus:status];
        }
        return nil;
    }
    
    // number of results
    CFIndex length = CFArrayGetCount(result);

    if( length <= 0 ) return [NSArray array];
    
    NSMutableArray *userNames = [NSMutableArray arrayWithCapacity:(NSUInteger)length];
    
    // Enumerate
    CFStringRef account;
    for ( CFIndex index = 0; index < length; index++ ) {
        CFDictionaryRef dict = CFArrayGetValueAtIndex(result, index);
        if( (account = CFDictionaryGetValue(dict, kSecAttrAccount)) ){
            [userNames addObject: (__bridge NSString *)account];
        }
    }
    
    CFRelease(result);
    
    return [NSArray arrayWithArray:userNames];
}


- (BOOL)setPassword:(NSString *)password forAccount:(NSString *)account andService:(NSString *)service error:(NSError * __autoreleasing *)error {
    return [self setData:[password dataUsingEncoding: NSUTF8StringEncoding] forAccount:account andService:service error:error];
}


- (NSString *)passwordForAccount:(NSString *)account andService:(NSString *)service error:(NSError * __autoreleasing *)error {
    
    // nil error
    if( error != NULL ) *error = nil;
    
    NSError *getDataError = nil;
    NSData *data = [self dataForAccount:account andService:service error:&getDataError];
    
    if( getDataError ){
        if( error != NULL ) *error = getDataError;
        return nil;
    }
    
    return (data?[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]:nil);
}


- (BOOL)setPropertyList:(id)object forAccount:(NSString *)account andService:(NSString *)service error:(NSError * __autoreleasing *)error {

    // nil error
    if( error != NULL ) *error = nil;
    
    NSError *serializationError = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList: object
                                                              format: NSPropertyListBinaryFormat_v1_0
                                                             options: 0
                                                               error: &serializationError];

    if( serializationError ){
        if ( error != NULL ) *error = [NSError errorWithDomain:RRKeychainErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey:serializationError}];
        return NO;
    }

    return [self setData:data forAccount:account andService:service error:error];
}


- (id)propertyListForAccount:(NSString *)account andService:(NSString *)service error:(NSError * __autoreleasing *)error {

    // nil error
    if( error != NULL ) *error = nil;
    
    NSError *getDataError = nil;
    NSData *data = [self dataForAccount:account andService:service error:&getDataError];
    
    if( getDataError ){
        if( error != NULL ) *error = getDataError;
        return nil;
    }
    
    NSString *serializationError = nil;
    id propertyList = [NSPropertyListSerialization propertyListFromData: data
                                                       mutabilityOption: NSPropertyListImmutable
                                                                 format: NULL
                                                       errorDescription: &serializationError];

    if( serializationError ){
        if ( error != NULL ) *error = [NSError errorWithDomain:RRKeychainErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey:serializationError}];
        return nil;
    }

    return propertyList;
}


- (BOOL)setData:(NSData *)data forAccount:(NSString *)account andService:(NSString *)service error:(NSError * __autoreleasing *)error {
    
    // nil error
    if( error != NULL ) *error = nil;

    // remove old one if it exists - I guess update would be safer...
    NSError *removeDataError = nil;
    if( [self dataForAccount:account andService:service error:&removeDataError] ){
        [self removeRecordForAccount:account andService:service error:&removeDataError];
    }
    
    if( removeDataError ){
        if( error != NULL ) *error = removeDataError;
        return NO;
    }

    // create query
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(query, kSecClass,          kSecClassGenericPassword);
    CFDictionaryAddValue(query, kSecValueData,      (__bridge const void *)data);
    CFDictionaryAddValue(query, kSecAttrAccount,    (__bridge const void *)account);
    CFDictionaryAddValue(query, kSecAttrService,    (__bridge const void *)service);
    
    OSStatus status = SecItemAdd(query, NULL);
    CFRelease(query);
    
    // did we got error?
    if( status != errSecSuccess ) {
        if ( error != NULL ) *error = [self errorForOSStatus:status];
        return NO;
    }
    
    return YES;
}


- (NSData *)dataForAccount:(NSString *)account andService:(NSString *)service error:(NSError * __autoreleasing *)error {
    
    // nil error
    if( error != NULL ) *error = nil;

    // create query
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(query, kSecReturnData,     kCFBooleanTrue);
    CFDictionaryAddValue(query, kSecMatchLimit,     kSecMatchLimitOne);
    CFDictionaryAddValue(query, kSecClass,          kSecClassGenericPassword);
    CFDictionaryAddValue(query, kSecAttrAccount,    (__bridge const void *)account);
    CFDictionaryAddValue(query, kSecAttrService,    (__bridge const void *)service);
    
    // perform query
    CFDataRef result = nil;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&result);
    CFRelease(query);
    
    // did we got error?
    if( status != errSecSuccess ) {
        if( status == errSecItemNotFound ) return nil;
        
        if ( error != NULL ) *error = [self errorForOSStatus:status];
        return nil;
    }

    return (NSData *)CFBridgingRelease(result);
}


- (BOOL)removeRecordForAccount:(NSString *)account andService:(NSString *)service error:(NSError * __autoreleasing *)error {
    
    // nil error
    if( error != NULL ) *error = nil;
    
    // create query
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(query, kSecClass,          kSecClassGenericPassword);
    CFDictionaryAddValue(query, kSecAttrService,    (__bridge const void *)(service));
    CFDictionaryAddValue(query, kSecAttrAccount,    (__bridge const void *)(account));

    // perform query
	OSStatus status = SecItemDelete(query);
    CFRelease(query);
    
    // did we got error?
    if( status != errSecSuccess ) {
        if ( error != NULL ) {
            *error = [self errorForOSStatus:status];
        }
        return NO;
    }

    return YES;
}


@end
