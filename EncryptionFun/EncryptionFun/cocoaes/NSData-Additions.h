//
//  NSData-Additions.h
//  2012 Joon You
//
//  Created by Joon You 11/17/2012
//

#import <Foundation/Foundation.h>


@interface NSData (NSData_Additions)

- (NSString *)newStringInBase64FromData;
- (NSData *)AES256DecryptWithKey:(NSString *)key iv:(NSString *)iv;
- (NSData*)AES256EncryptWithKey:(NSString*)key iv:(NSString*)iv;

@end
