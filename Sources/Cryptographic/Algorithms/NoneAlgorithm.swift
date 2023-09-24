//
//  NoneAlgorithm.swift
//  clean-mvvmc-master
//
//  Created by Developer on 22/09/2023.
//

import Foundation

/// An EncryptionAlgorithm representing an alg of "none" in a JWT.
/// Using this algorithm means the header and claims will not be signed or verified.
struct NoneAlgorithm: VerifierAlgorithm, SignerAlgorithm {
    
    let name: String = "none"
    
    
    func sign(header: String, payload: String) -> String {
        return header + "." + payload
    }
    
    func verify(jwt: String) -> Bool {
        return true
    }
}
