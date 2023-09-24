//
//  Status.swift
//  clean-mvvmc-master
//
//  Created by Developer on 22/09/2023.
//

import Foundation
import CommonCrypto

public enum Status: CCCryptorStatus, Swift.Error, CustomStringConvertible {
    
    /// Successful
    case success
    
    /// Parameter Error
    case paramError
    
    /// Buffer too Small
    case bufferTooSmall
    
    /// Memory Failure
    case memoryFailure
    
    /// Alignment Error
    case alignmentError
    
    /// Decode Error
    case decodeError
    
    /// Unimplemented
    case unimplemented
    
    /// Overflow
    case overflow
    
    /// Random Number Generator Err
    case rngFailure
    
    public func toRaw() -> CCCryptorStatus {
        switch self {
        case .success:
            return CCCryptorStatus(kCCSuccess)
        case .paramError:
            return CCCryptorStatus(kCCParamError)
        case .bufferTooSmall:
               return CCCryptorStatus(kCCBufferTooSmall)
        case .memoryFailure:
            return CCCryptorStatus(kCCMemoryFailure)
        case .alignmentError:
               return CCCryptorStatus(kCCAlignmentError)
        case .decodeError:
            return CCCryptorStatus(kCCDecodeError)
        case .unimplemented:
            return CCCryptorStatus(kCCUnimplemented)
        case .overflow:
            return CCCryptorStatus(kCCOverflow)
        case .rngFailure:
            return CCCryptorStatus(kCCRNGFailure)
        }
    }
    
    ///
    /// Human readable descriptions of the values. (Not needed in Swift 2.0?)
    ///
    static let descriptions = [
        success: "Success",
        paramError: "ParamError",
        bufferTooSmall: "BufferTooSmall",
        memoryFailure: "MemoryFailure",
        alignmentError: "AlignmentError",
        decodeError: "DecodeError",
        unimplemented: "Unimplemented",
        overflow: "Overflow",
        rngFailure: "RNGFailure"
    ]
    
    ///
    /// Obtain human-readable string from enum value.
    ///
    public var description: String {
        return (Status.descriptions[self] != nil) ? Status.descriptions[self]! : ""
    }
    
    ///
    /// Create enum value from raw `CCCryptorStatus` value.
    ///
    public static func fromRaw(status: CCCryptorStatus) -> Status? {
        let from = [
            kCCSuccess: success,
            kCCParamError: paramError,
            kCCBufferTooSmall: bufferTooSmall,
            kCCMemoryFailure: memoryFailure,
            kCCAlignmentError: alignmentError,
            kCCDecodeError: decodeError,
            kCCUnimplemented: unimplemented,
            kCCOverflow: overflow,
            kCCRNGFailure: rngFailure
        ]
        
        return from[Int(status)]
    }
}


public enum CryptorError: Swift.Error, CustomStringConvertible {
    
    /// Success
    case success
    
    /// Invalid key size
    case invalidKeySize
    
    /// Invalid IV size
    case invalidIVSizeOrLength
    
    /// Fail with code and string
    case fail(Int32, String)
    
    /// The error code itself
    public var errCode: Int32 {
        
        switch self {
            
        case .success:
            return 0
            
        case .invalidKeySize:
            return -1
            
        case .invalidIVSizeOrLength:
            return -2
            
        case .fail(let errCode, _):
            return Int32(errCode)
        }
    }
    
    /// Error Description
    public var description: String {
        
        switch self {
            
        case .success:
            return "Success"
            
        case .invalidKeySize:
            return "Invalid key size."
            
        case .invalidIVSizeOrLength:
            return "Invalid IV size or length."
            
        case .fail(_, let reason):
            return reason
        }
    }
}
