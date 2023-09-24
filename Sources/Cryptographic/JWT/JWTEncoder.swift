//
//  JWTEncoder.swift
//  clean-mvvmc-master
//
//  Created by Developer on 21/09/2023.
//

import Foundation
import CodeBureau

public class JWTEncoder: BodyEncoder {
    
    let keyIDToSigner: (String) -> JWTSigner?
    let jwtSigner: JWTSigner?
    
    // MARK: Initializers
    
    /// Initialize a `JWTEncoder` instance with a single `JWTSigner`.
    ///
    /// - Parameter jwtSigner: The `JWTSigner` that will be used to sign the JWT.
    /// - Returns: A new instance of `JWTEncoder`.
    public init(jwtSigner: JWTSigner) {
        self.keyIDToSigner = { _ in return jwtSigner }
        self.jwtSigner = jwtSigner
    }
    
    /// Initialize a `JWTEncoder` instance with a function to generate the `JWTSigner` from the JWT `kid` header.
    ///
    /// - Parameter keyIDToSigner: The function to generate the `JWTSigner` from the JWT `kid` header.
    /// - Returns: A new instance of `JWTEncoder`.
    public init(keyIDToSigner: @escaping (String) -> JWTSigner?) {
        self.keyIDToSigner = keyIDToSigner
        self.jwtSigner = nil
    }
    
    // MARK: Encode
    
    /// Encode a `JWT` instance into a UTF8 encoded JWT String.
    ///
    /// - Parameter value: The JWT instance to be encoded as Data.
    /// - Returns: The UTF8 encoded JWT String.
    /// - throws: `JWTError.invalidUTF8Data` if the provided Data can't be decoded to a String.
    /// - throws: `JWTError.invalidKeyID` if the KeyID `kid` header fails to generate a jwtSigner.
    /// - throws: `EncodingError` if the encoder fails to encode the object as Data.
    public func encode<T : Encodable>(_ value: T) throws -> Data {
        guard let jwt = try self.encodeToString(value).data(using: .utf8) else {
            throw JWTError.invalidUTF8Data
        }
        
        return jwt
    }
    
    /// Encode a `JWT` instance as a JWT String.
    ///
    /// - Parameter value: The JWT instance to be encoded as a JWT String.
    /// - Returns: A JWT String.
    /// - throws: `JWTError.invalidKeyID` if the KeyID `kid` header fails to generate a jwtSigner.
    /// - throws: `EncodingError` if the encoder fails to encode the object as Data.
    public func encodeToString<T : Encodable>(_ value: T) throws -> String {
        let encoder = _JWTEncoder(jwtSigner: jwtSigner, keyIDToSigner: keyIDToSigner)
        
        try value.encode(to: encoder)
        
        guard let header = encoder.header,
              let payload = encoder.payload,
              let jwtSigner = encoder.jwtSigner
        else {
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: [], debugDescription: "Failed to sign JWT Header and Payload."))
        }
        
        return try jwtSigner.sign(header: header, payload: payload)
    }
}


fileprivate class _JWTEncoder: Encoder {
    
    var payload: String?
    
    var header: String?
    
    var jwtSigner: JWTSigner?
    
    let keyIDToSigner: (String) -> JWTSigner?
    
    var codingPath: [CodingKey] = []
    
    var userInfo: [CodingUserInfoKey : Any] = [:]
    
    
    init(jwtSigner: JWTSigner?, keyIDToSigner: @escaping (String) -> JWTSigner?) {
        self.jwtSigner = jwtSigner
        self.keyIDToSigner = keyIDToSigner
    }
    
    
    func container<Key : CodingKey>(keyedBy type: Key.Type) -> KeyedEncodingContainer<Key> {
        let container = _JWTKeyedEncodingContainer<Key>(encoder: self, codingPath: self.codingPath)
        return KeyedEncodingContainer(container)
    }
    
    
    private struct _JWTKeyedEncodingContainer<Key: CodingKey>: KeyedEncodingContainerProtocol {
        
        /// A reference to the encoder we're writing to.
        let encoder: _JWTEncoder
        
        var codingPath: [CodingKey]
        
        // Set the Encoder header and claims Strings using the container
        mutating func encode<T: Encodable>(_ value: T, forKey key: Key) throws {
            self.codingPath.append(key)
            
            let fieldName = key.stringValue
            let jsonEncoder = JSONEncoder()
            jsonEncoder.dateEncodingStrategy = .secondsSince1970
            
            if fieldName == "header" {
                guard var _header = value as? Header else {
                    throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: [], debugDescription: "Failed to encode into header CodingKey"))
                }
                
                // Set the jwtSigner while you have acces to the keyID
                if encoder.jwtSigner == nil {
                    
                    guard let keyID = _header.kid,
                          let keyIDJWTSigner = encoder.keyIDToSigner(keyID)
                    else {
                        throw JWTError.invalidKeyID
                    }
                    
                    encoder.jwtSigner = keyIDJWTSigner
                }
                
                _header.alg = encoder.jwtSigner?.name
                
                let data = try jsonEncoder.encode(_header)
                encoder.header = JWTEncoder.base64urlEncodedString(data: data)
                
            } else if fieldName == "payload" {
                
                let data = try jsonEncoder.encode(value)
                encoder.payload = JWTEncoder.base64urlEncodedString(data: data)
            }
        }
        
        // No functions beyond this point should be called for encoding a JWT token
        mutating func nestedContainer<NestedKey>(keyedBy keyType: NestedKey.Type, forKey key: Key) -> KeyedEncodingContainer<NestedKey> where NestedKey: CodingKey {
            return encoder.container(keyedBy: keyType)
        }
        
        mutating func nestedUnkeyedContainer(forKey key: Key) -> UnkeyedEncodingContainer {
            return encoder.unkeyedContainer()
        }
        
        mutating func superEncoder() -> Encoder {
            return encoder
        }
        
        mutating func superEncoder(forKey key: Key) -> Encoder {
            return encoder
        }
        
        // Throw if trying to encode something other than a JWT token
        mutating func encodeNil(forKey key: Key) throws {
            throw EncodingError.invalidValue(key, EncodingError.Context(codingPath: codingPath, debugDescription: "JWTEncoder can only encode JWT tokens"))
        }

    }
    
    func unkeyedContainer() -> UnkeyedEncodingContainer {
        return UnkeyedContainer(encoder: self)
    }
    
    func singleValueContainer() -> SingleValueEncodingContainer {
        return UnkeyedContainer(encoder: self)
    }
    
    
    // This Decoder should not be used to decode UnkeyedContainer
    private struct UnkeyedContainer: UnkeyedEncodingContainer, SingleValueEncodingContainer {
        
        var encoder: _JWTEncoder
        
        var codingPath: [CodingKey] {
            return []
        }
        
        var count: Int {
            return 0
        }
        
        
        func nestedContainer<NestedKey>(keyedBy keyType: NestedKey.Type) -> KeyedEncodingContainer<NestedKey> where NestedKey: CodingKey {
            return encoder.container(keyedBy: keyType)
        }
        
        func nestedUnkeyedContainer() -> UnkeyedEncodingContainer {
            return self
        }
        
        func superEncoder() -> Encoder {
            return encoder
        }
        
        func encodeNil() throws {}
        
        
        func encode<T>(_ value: T) throws where T: Encodable {
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: codingPath, debugDescription: "JWTEncoder can only encode JWT tokens."))
        }
    }
}

/// Convenience extension for encoding a `Data` as a base64url-encoded `String`.
extension JWTEncoder {

    /// Returns a `String` representation of this data, encoded in base64url format
    /// as defined in RFC4648 (https://tools.ietf.org/html/rfc4648).
    ///
    /// This is the appropriate format for encoding the header and claims of a JWT.
    static func base64urlEncodedString(data: Data) -> String {
        let result = data.base64EncodedString()
        
        return result.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
