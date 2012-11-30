//
//  main.m
//  EncryptionFun
//
//  Created by Joon You on 11/29/12.
//  Copyright (c) 2012 Joon You. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "NSData+Base64.h"
#import "NSData-Additions.h"

int main(int argc, const char * argv[])
{

  @autoreleasepool {
    NSString *key = @"a0e12d601e10154fe5743fd6d2ba3749";
    NSString *iv = @"15485aefa2f6ef6cf669d040fe60d3f6e55a948848cc7f11feb857f845daf9a0";
    
    NSURL *url = [NSURL URLWithString:@"http://localhost:3000/encrypts"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:@"POST"];
    NSString *secretContent = @"secret";
    
    NSData *secretData = [[secretContent dataUsingEncoding:NSUTF8StringEncoding] AES256EncryptWithKey:key iv:iv];
    NSString *encryptedString = [secretData newStringInBase64FromData];
    
    NSString *params = [NSString stringWithFormat:@"psst=%@", encryptedString];
    NSData *postData = [params dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    
    [request setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    [request setValue:[NSString stringWithFormat:@"%ld",[postData length]] forHTTPHeaderField:@"Content-Length"];
    [request setHTTPBody:postData];
    
    NSURLResponse *response;
    NSError *error;
    
    NSData *responseData = [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:&error];
    NSString *result = [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
    NSLog(@"responseData: %@", result);
    [result release];
    
  }
    return 0;
}


