//
//  CodesignChecker.swift
//  PrivilegedTaskRunner
//
//  Created by Antti Tulisalo on 20/09/2018.
//

// Based loosely on Objectice-C code of this: https://github.com/NBICreator/NBICreator/blob/master/NBICreator/Helper/SNTCodesignChecker.m

/*
 
 Workflow in the user (Privileged helper) of this utility struct should go something like this:
 
    let checker = CodesignChecker()
    let pid = connection.processIdentifier
 
    let certs1 = checker.prepareWithSelf()
    let certs2 = checker.prepareWithPID(pid: pid)

    let remoteApp = NSRunningApplication.init(processIdentifier: pid)
 
    // Then compare cert arrays and that remoteApp exists
    if(remoteApp != nil && (certs1 == certs2)) {
    return true
 */

import Foundation
import Security

struct CodesignChecker {

    // This is from ported code, I think not needed like this so defaults should be ok
    //let secFlags = SecCSFlags.init(rawValue: kSecCSDoNotValidateResources | kSecCSCheckNestedCode)
    
    // Swift API lacks 'kSecCSDefaultFlags' AFAIK, but it should be zero anyway, so..
    let secFlags = SecCSFlags.init(rawValue: 0)
    
    func validateWithSecStaticCodeRef(codeRef: SecCode?) -> [Any] {
        
        NSLog("TypeID: \(CFGetTypeID(codeRef))")
        NSLog("Static: \(SecStaticCodeGetTypeID())")
        if(CFGetTypeID(codeRef) == SecStaticCodeGetTypeID()) { // For some reason this line always fails for me
            NSLog("1")
            if(SecStaticCodeCheckValidity(codeRef! as! SecStaticCode, SecCSFlags.init(rawValue: kSecCSBasicValidateOnly), nil) == errSecSuccess) {
              NSLog("Signing is valid!")
                // Continue to do the rest of the stuff (certificate array)
            }
        }
        else {
            NSLog("Jumps straight at here for some reason")
        }

        // Returns an array of 'kSecCodeInfoCertificates'
        return []
    }
    
    func prepareWithPID(pid: pid_t) -> [Any] {

        var codeSelf: SecCode?
        //var resultCode: OSStatus
        
        let attributes = [
            kSecGuestAttributePid : pid
        ]
        
        if(SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, SecCSFlags.init(rawValue: 0), &codeSelf) == errSecSuccess) {
            
            _ = validateWithSecStaticCodeRef(codeRef: codeSelf)
        }
        
        // Returns an array of 'kSecCodeInfoCertificates'
        return []
    }
    
    func prepareWithSelf() -> [Any] {
        
        var codeSelf: SecCode?
        //var resultCode: OSStatus

        if(SecCodeCopySelf(SecCSFlags.init(rawValue: 0), &codeSelf) == errSecSuccess) {
            // Then should do this as well
            //self.validateWithSecStaticCodeRef(codeRef: codeSelf)
        }
        
        // Returns an array of 'kSecCodeInfoCertificates'
        return []
    }
}
