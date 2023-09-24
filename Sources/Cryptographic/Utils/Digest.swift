//
//  Digest.swift
//  clean-mvvmc-master
//
//  Created by Developer on 22/09/2023.
//

import Foundation
import CommonCrypto

public class Digest {
    
    public var status = Status.success
    
    
    public enum Algorithm {
        
        /// Secure Hash Algorithm 1
        case sha1
        
        /// Secure Hash Algorithm 2 224-bit
        case sha224
        
        /// Secure Hash Algorithm 2 256-bit
        case sha256
        
        /// Secure Hash Algorithm 2 384-bit
        case sha384
        
        /// Secure Hash Algorithm 2 512-bit
        case sha512
    }
    
    
    private var engine: DigestEngine
    
    
    public init(using algorithm: Algorithm) {
        switch algorithm {
        case .sha1:
            engine = DigestEngineCC<CC_SHA1_CTX>(initializer: CC_SHA1_Init, updater: CC_SHA1_Update, finalizer: CC_SHA1_Final, length: CC_SHA1_DIGEST_LENGTH)
        case .sha224:
            engine = DigestEngineCC<CC_SHA256_CTX>(initializer: CC_SHA224_Init, updater: CC_SHA224_Update, finalizer: CC_SHA224_Final, length: CC_SHA224_DIGEST_LENGTH)
        case .sha256:
            engine = DigestEngineCC<CC_SHA256_CTX>(initializer: CC_SHA256_Init, updater: CC_SHA256_Update, finalizer: CC_SHA256_Final, length: CC_SHA256_DIGEST_LENGTH)
        case .sha384:
            engine = DigestEngineCC<CC_SHA512_CTX>(initializer: CC_SHA384_Init, updater: CC_SHA384_Update, finalizer: CC_SHA384_Final, length: CC_SHA384_DIGEST_LENGTH)
        case .sha512:
            engine = DigestEngineCC<CC_SHA512_CTX>(initializer: CC_SHA512_Init, updater: CC_SHA512_Update, finalizer: CC_SHA512_Final, length: CC_SHA512_DIGEST_LENGTH)
        }
    }
    
    ///
    ///    Low-level update routine. Updates the message digest calculation with
    ///    the contents of a byte buffer.
    ///
    /// - Parameters:
     ///        - buffer:        The buffer
    ///        - byteCount:     Number of bytes in buffer
    ///
    /// - Returns: This Digest object (for optional chaining)
    ///
    public func update(from buffer: UnsafeRawPointer, byteCount: size_t) -> Self? {
        engine.update(buffer: buffer, byteCount: CC_LONG(byteCount))
        
        return self
    }
    
    ///
    ///    Completes the calculate of the messge digest
    ///
    /// - Returns: The message digest
    ///
    public func final() -> [UInt8] {
        return engine.final()
    }
}


// MARK: Internal Classes

///
/// Defines the interface between the Digest class and an
/// algorithm specific DigestEngine
///
private protocol DigestEngine {

    ///
    /// Update method
    ///
    /// - Parameters:
    ///        - buffer:        The buffer to add.
    ///        - byteCount:    The length of the buffer.
    ///
    func update(buffer: UnsafeRawPointer, byteCount: CC_LONG)
    
    ///
    /// Finalizer routine
    ///
    /// - Returns: Byte array containing the digest.
    ///
    func final() -> [UInt8]
}

///
///    Wraps the underlying algorithm specific structures and calls
///    in a generic interface.
///
/// - Parameter CTX:    The context for the digest.
///
private class DigestEngineCC<CTX>: DigestEngine {
    
    typealias Context = UnsafeMutablePointer<CTX>
    typealias Buffer = UnsafeRawPointer
    typealias Digest = UnsafeMutablePointer<UInt8>
    typealias Initializer = (Context) -> (Int32)
    typealias Updater = (Context, Buffer, CC_LONG) -> (Int32)
    typealias Finalizer = (Digest, Context) -> (Int32)
    
    let context = Context.allocate(capacity: 1)
    var initializer: Initializer
    var updater: Updater
    var finalizer: Finalizer
    var length: Int32
    
    ///
    /// Default initializer
    ///
    /// - Parameters:
    ///        - initializer:     The digest initializer routine.
    ///     - updater:        The digest updater routine.
    ///     - finalizer:    The digest finalizer routine.
    ///     - length:        The digest length.
    ///
    init(initializer: @escaping Initializer, updater: @escaping Updater, finalizer: @escaping Finalizer, length: Int32) {
        
        self.initializer = initializer
        self.updater = updater
        self.finalizer = finalizer
        self.length = length
        
        _ = initializer(context)
    }
    
    ///
    /// Cleanup
    ///
    deinit {
        
        #if swift(>=4.1)
            context.deallocate()
        #else
            context.deallocate(capacity: 1)
        #endif
    }
    
    ///
    /// Update method
    ///
    /// - Parameters:
    ///        - buffer:        The buffer to add.
    ///        - byteCount:    The length of the buffer.
    ///
    func update(buffer: Buffer, byteCount: CC_LONG) {
        
        _ = updater(context, buffer, byteCount)
    }
    
    ///
    /// Finalizer routine
    ///
    /// - Returns: Byte array containing the digest.
    ///
    func final() -> [UInt8] {
        
        let digestLength = Int(self.length)
        var digest = Array<UInt8>(repeating: 0, count:digestLength)
        
        _ = finalizer(&digest, context)
        
        return digest
    }
}
