//
//  BlueHMAC.swift
//  clean-mvvmc-master
//
//  Created by Developer on 21/09/2023.
//

import Foundation

class BlueHMAC: SignerAlgorithm, VerifierAlgorithm {
    
    private let key: Data
    private let algorithm: HMAC.Algorithm
    
    
    init(key: Data, algorithm: HMAC.Algorithm) {
        self.key = key
        self.algorithm = algorithm
    }
    
    
    func sign(header: String, payload: String) throws -> String {
        let unsignedJWT = header + "." + payload
        
        guard let unsignedData = unsignedJWT.data(using: .utf8) else {
            throw JWTError.invalidJWTString
        }
        
        let signature = try sign(unsignedData)
        let signatureString = JWTEncoder.base64urlEncodedString(data: signature)
        
        return header + "." + payload + "." + signatureString
    }
    
    func sign(_ data: Data) throws -> Data {
        guard #available(macOS 10.12, iOS 10.0, *) else {
            print("macOS 10.12.0 (Sierra) or higher or iOS 10.0 or higher is required by Cryptor")
            throw JWTError.osVersionToLow
        }
        
        guard let hmac = HMAC(using: algorithm, key: key)
            .update(data: data)?
            .final()
        else {
            throw JWTError.invalidPrivateKey
        }
        
        #if swift(>=5.0)
        return Data(hmac)
        #else
        return Data(bytes: hmac)
        #endif
    }
    
    func verify(jwt: String) -> Bool {
        let components = jwt.components(separatedBy: ".")
        
        if components.count == 3 {
            guard let signature = JWTDecoder.data(base64urlEncoded: components[2]),
                  let jwtData = (components[0] + "." + components[1]).data(using: .utf8)
            else {
                return false
            }
            
            return self.verify(signature: signature, for: jwtData)
        } else {
            return false
        }
    }
    
    func verify(signature: Data, for data: Data) -> Bool {
        guard #available(macOS 10.12, iOS 10.0, *) else {
            return false
        }
        
        do {
            let expectedHMAC = try sign(data)
            
            return expectedHMAC == signature
        } catch {
            return false
        }
    }
}
