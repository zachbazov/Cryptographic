//
//  JWTVerifier.swift
//  clean-mvvmc-master
//
//  Created by Developer on 21/09/2023.
//

import Foundation

public struct JWTVerifier {
    
    let verifierAlgorithm: VerifierAlgorithm
    
    
    init(verifierAlgorithm: VerifierAlgorithm) {
        self.verifierAlgorithm = verifierAlgorithm
    }
    
    
    func verify(jwt: String) -> Bool {
        return verifierAlgorithm.verify(jwt: jwt)
    }
    
    
    /// Initialize a JWTSigner using the HMAC 256 bits algorithm and the provided privateKey.
    /// - Parameter key: The HMAC symmetric password data.
    public static func hs256(key: Data) -> JWTVerifier {
        return JWTVerifier(verifierAlgorithm: BlueHMAC(key: key, algorithm: .sha256))
    }
    
    /// Initialize a JWTVerifier that will always return true when verifying the JWT. This is equivelent to using the "none" alg header.
    public static let none = JWTVerifier(verifierAlgorithm: NoneAlgorithm())
}
