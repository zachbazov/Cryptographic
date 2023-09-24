//
//  JWTDecoder.swift
//  clean-mvvmc-master
//
//  Created by Developer on 21/09/2023.
//

import Foundation
import CodeBureau

protocol JWTDecodable: BodyDecoder {
    
    var keyIDToVerifier: (String) -> JWTVerifier? { get }
    var jwtVerifier: JWTVerifier? { get }
    
    func decode<T>(_ type: T.Type, fromString: String) throws -> T where T: Decodable
}

public class JWTDecoder: JWTDecodable {
    
    let keyIDToVerifier: (String) -> JWTVerifier?
    
    let jwtVerifier: JWTVerifier?
    
    
    public init(jwtVerifier: JWTVerifier) {
        self.keyIDToVerifier = { _ in return jwtVerifier }
        self.jwtVerifier = jwtVerifier
    }
    
    public init(keyIDToVerifier: @escaping (String) -> JWTVerifier?) {
        self.keyIDToVerifier = keyIDToVerifier
        self.jwtVerifier = nil
    }
    
    
    public func decode<T>(_ type: T.Type, fromString: String) throws -> T where T: Decodable {
        let components = fromString.components(separatedBy: ".")
        
        guard components.count > 1,
              let headerData = JWTDecoder.data(base64urlEncoded: components[0]),
              let payloadData = JWTDecoder.data(base64urlEncoded: components[1])
        else {
            throw JWTError.invalidJWTString
        }
        
        let decoder = _JWTDecoder(header: headerData, payload: payloadData)
        let jwt = try decoder.decode(type)
        
        let _jwtVerifier: JWTVerifier
        
        if let jwtVerifier = jwtVerifier {
            _jwtVerifier = jwtVerifier
        } else {
            guard let keyID = decoder.keyID,
                  let jwtVerifier = keyIDToVerifier(keyID)
            else {
                throw JWTError.invalidKeyID
            }
            
            _jwtVerifier = jwtVerifier
        }
        
        guard _jwtVerifier.verify(jwt: fromString) else {
            throw JWTError.failedVerification
        }
        
        return jwt
    }
    
    public func decode<T>(_ type: T.Type, from data: Data) throws -> T where T: Decodable {
        guard let jwtString = String(data: data, encoding: .utf8) else {
            throw JWTError.invalidUTF8Data
        }
        
        return try decode(type, fromString: jwtString)
    }
}


fileprivate class _JWTDecoder: Decoder {
    
    var header: Data
    
    var payload: Data
    
    var keyID: String?
    
    var codingPath: [CodingKey] = []
    
    var userInfo: [CodingUserInfoKey: Any] = [:]
    
    
    init(header: Data, payload: Data) {
        self.header = header
        self.payload = payload
    }
    
    
    public func decode<T: Decodable>(_ type: T.Type) throws -> T {
        return try type.init(from: self)
    }
    
    
    func container<Key>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> where Key: CodingKey {
        let container = _JWTKeyedDecodingContainer<Key>(decoder: self, header: header, payload: payload)
        return KeyedDecodingContainer(container)
    }
    
    func unkeyedContainer() throws -> UnkeyedDecodingContainer {
        return UnkeyedContainer(decoder: self)
    }
    
    func singleValueContainer() throws -> SingleValueDecodingContainer {
        return UnkeyedContainer(decoder: self)
    }
}


private struct _JWTKeyedDecodingContainer<Key: CodingKey>: KeyedDecodingContainerProtocol {
    
    let decoder: _JWTDecoder
    
    var header: Data
    
    var payload: Data
    
    var codingPath: [CodingKey]
    
    public var allKeys: [Key] {
        #if swift(>=4.1)
        return ["header", "payload"].compactMap { Key(stringValue: $0) }
        #else
        return ["header", "payload"].flatMap { Key(stringValue: $0) }
        #endif
    }
    
    
    fileprivate init(decoder: _JWTDecoder, header: Data, payload: Data) {
        self.decoder = decoder
        self.header = header
        self.payload = payload
        self.codingPath = decoder.codingPath
    }
    
    
    public func contains(_ key: Key) -> Bool {
        return key.stringValue == "header" || key.stringValue == "payload"
    }
    
    func decode<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T {
        
        decoder.codingPath.append(key)
        
        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        
        if key.stringValue == "header" {
            let header = try jsonDecoder.decode(Header.self, from: self.header)
            
            decoder.keyID = header.kid
            
            guard let decoderHeader = header as? T else {
                throw DecodingError.typeMismatch(T.self, DecodingError.Context(codingPath: codingPath, debugDescription: "Type of header key was not a JWT Header."))
            }
            
            return decoderHeader
            
        } else {
            
            if key.stringValue == "payload" {
                return try jsonDecoder.decode(type, from: self.payload)
            } else {
                throw DecodingError.keyNotFound(key, DecodingError.Context(codingPath: codingPath, debugDescription: "value not found for provided key."))
            }
        }
    }
    
    func decodeNil(forKey key: Key) throws -> Bool {
        throw DecodingError.typeMismatch(Key.self, DecodingError.Context(codingPath: codingPath, debugDescription: "JWTDecoder can only decode JWT tokens."))
    }
    
    func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type, forKey key: Key) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
        return try decoder.container(keyedBy: type)
    }
    
    func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
        return try decoder.unkeyedContainer()
    }
    
    func superDecoder() throws -> Decoder {
        return decoder
    }
    
    func superDecoder(forKey key: Key) throws -> Decoder {
        return decoder
    }
}


private struct UnkeyedContainer: UnkeyedDecodingContainer, SingleValueDecodingContainer {
    
    var decoder: _JWTDecoder
    
    var codingPath: [CodingKey] {
        return []
    }
    
    var count: Int? {
        return nil
    }
    
    var currentIndex: Int {
        return .zero
    }
    
    var isAtEnd: Bool {
        return false
    }
    
    
    func decode<T>(_ type: T.Type) throws -> T where T: Decodable {
        throw DecodingError.typeMismatch(type, DecodingError.Context(codingPath: codingPath, debugDescription: "JWTDecoder can only Decode JWT tokens."))
    }
    
    func decodeNil() -> Bool {
        return true
    }
    
    func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
        return try decoder.container(keyedBy: type)
    }
    
    func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
        return self
    }
    
    func superDecoder() throws -> Decoder {
        return decoder
    }
}


extension JWTDecoder {
    
    static func data(base64urlEncoded: String) -> Data? {
        let paddingLength = 4 - base64urlEncoded.count % 4
        let padding = (paddingLength < 4) ? String(repeating: "=", count: paddingLength) : ""
        let base64EncodedString = base64urlEncoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + padding
        return Data(base64Encoded: base64EncodedString)
    }
}
