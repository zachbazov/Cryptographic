//
//  JWTError.swift
//  clean-mvvmc-master
//
//  Created by Developer on 22/09/2023.
//

import Foundation

/// A struct representing the different errors that can be thrown by SwiftJWT
public struct JWTError: LocalizedError, Equatable {

    /// A human readable description of the error.
    public let errorDescription: String?
    
    private let internalError: InternalError
    
    private enum InternalError {
        case invalidJWTString, failedVerification, osVersionToLow, invalidPrivateKey, invalidData, invalidKeyID, missingPEMHeaders
    }
    
    /// Error when an invalid JWT String is provided
    public static let invalidJWTString = JWTError(errorDescription: "Input was not a valid JWT String", internalError: .invalidJWTString)
    
    /// Error when the JWT signiture fails verification.
    public static let failedVerification = JWTError(errorDescription: "JWT verifier failed to verify the JWT String signiture", internalError: .failedVerification)
    
    /// Error when using RSA encryption with an OS version that is too low.
    public static let osVersionToLow = JWTError(errorDescription: "macOS 10.12.0 (Sierra) or higher or iOS 10.0 or higher is required by CryptorRSA", internalError: .osVersionToLow)
    
    /// Error when an invalid private key is provided for RSA encryption.
    public static let invalidPrivateKey = JWTError(errorDescription: "Provided private key could not be used to sign JWT", internalError: .invalidPrivateKey)
    
    /// Error when the provided Data cannot be decoded to a String
    public static let invalidUTF8Data = JWTError(errorDescription: "Could not decode Data from UTF8 to String", internalError: .invalidData)
    
    /// Error when the KeyID field `kid` in the JWT header fails to generate a JWTSigner or JWTVerifier
    public static let invalidKeyID = JWTError(errorDescription: "The JWT KeyID `kid` header failed to generate a JWTSigner/JWTVerifier", internalError: .invalidKeyID)
    
    /// Error when a PEM string is provided without the expected PEM headers/footers. (e.g. -----BEGIN PRIVATE KEY-----)
    public static let missingPEMHeaders = JWTError(errorDescription: "The provided key did not have the expected PEM headers/footers", internalError: .missingPEMHeaders)
    
    /// Function to check if JWTErrors are equal. Required for equatable protocol.
    public static func == (lhs: JWTError, rhs: JWTError) -> Bool {
        return lhs.internalError == rhs.internalError
    }

    /// Function to enable pattern matching against generic Errors.
    public static func ~= (lhs: JWTError, rhs: Error) -> Bool {
        guard let rhs = rhs as? JWTError else {
            return false
        }
        return lhs == rhs
    }
}

