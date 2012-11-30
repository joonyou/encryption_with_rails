//
//  NSData-Additions.m
//  2012 Joon You
//
//  Created by Joon You 11/17/2012
//

#import "NSData-Additions.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCryptor.h>

@implementation NSData (NSData_Additions)

static char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

- (NSString *)newStringInBase64FromData {
	NSMutableString *dest = [[NSMutableString alloc] initWithString:@""];
	unsigned char * working = (unsigned char *)[self bytes];
	int srcLen = [self length];
	
	// tackle the source in 3's as conveniently 4 Base64 nibbles fit into 3 bytes
	for (int i=0; i<srcLen; i += 3)
	{
		// for each output nibble
		for (int nib=0; nib<4; nib++)
		{
			// nibble:nib from char:byt
			int byt = (nib == 0)?0:nib-1;
			int ix = (nib+1)*2;
			
			if (i+byt >= srcLen) break;
			
			// extract the top bits of the nibble, if valid
			unsigned char curr = ((working[i+byt] << (8-ix)) & 0x3F);
			
			// extract the bottom bits of the nibble, if valid
			if (i+nib < srcLen) curr |= ((working[i+nib] >> ix) & 0x3F);
			
			[dest appendFormat:@"%c", base64[curr]];
		}
	}
	
	return dest;
}

- (NSData *)AES256DecryptWithKey:(NSString *)key iv:(NSString *)iv {
    // key size is 32 + 1 char for terminator
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[[iv length] + 1];
    bzero(ivPtr, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    // get data length
    NSUInteger dataLength = [self length];
    
    // create output buffer
    size_t bufferSize = dataLength + kCCKeySizeAES256;
    void *buffer = malloc(bufferSize);
    bzero(buffer, bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,    // we use kCCModeCBC
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          ivPtr,
                                          [self bytes],
                                          dataLength, /* input */
                                          buffer,
                                          bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        NSData *decryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
        
        return decryptedData;
    }
    
    free(buffer);
    return nil;
}

- (NSData*)AES256EncryptWithKey:(NSString*)key iv:(NSString*)iv {
  // 'key' should be 32 bytes for AES256, will be null-padded otherwise
  char keyPtr[kCCKeySizeAES256 + 1]; // room for terminator (unused)
  bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
  
  // fetch key data
  [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
  
  char ivPtr[[iv length] + 1];
  bzero(ivPtr, sizeof(ivPtr));
  [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
  
  NSUInteger dataLength = [self length];
  
  size_t bufferSize           = dataLength + kCCBlockSizeAES128;
  void* buffer                = malloc(bufferSize);
  
  size_t numBytesEncrypted    = 0;
  CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                        keyPtr, kCCKeySizeAES256,
                                        ivPtr,
                                        [self bytes], dataLength, /* input */
                                        buffer, bufferSize, /* output */
                                        &numBytesEncrypted);
  
  if (cryptStatus == kCCSuccess)
  {
    //the returned NSData takes ownership of the buffer and will free it on deallocation
    return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
  }
  
  free(buffer); //free the buffer;
  return nil;
}

@end
