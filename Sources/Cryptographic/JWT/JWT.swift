//
//  JWT.swift
//  clean-mvvmc-master
//
//  Created by Developer on 18/09/2023.
//

import Foundation

public struct JWT<T: Payload>: Codable {
    
    /// The JWT header.
    public var header: Header
    
    /// The JWT payload.
    public var payload: T
    
    /// Initialize a `JWT` instance from a `Header` and `Payload`.
    ///
    /// - Parameter header: A JSON Web Token header object.
    /// - Parameter payload: A JSON Web Token payload object.
    /// - Returns: A new instance of `JWT`.
    public init(header: Header = Header(), payload: T) {
        self.header = header
        self.payload = payload
    }
    
    /// Initialize a `JWT` instance from a JWT String.
    /// The signature will be verified using the provided JWTVerifier.
    /// The time based standard JWT payload will be verified with `validatePayload()`.
    /// If the string is not a valid JWT, or the verification fails, the initializer returns nil.
    ///
    /// - Parameter jwt: A String with the encoded and signed JWT.
    /// - Parameter verifier: The `JWTVerifier` used to verify the JWT.
    /// - Returns: An instance of `JWT` if the decoding succeeds.
    /// - Throws: `JWTError.invalidJWTString` if the provided String is not in the form mandated by the JWT specification.
    /// - Throws: `JWTError.failedVerification` if the verifier fails to verify the jwtString.
    /// - Throws: A DecodingError if the JSONDecoder throws an error while decoding the JWT.
    public init(jwtString: String, verifier: JWTVerifier) throws {
        
        let components = jwtString.components(separatedBy: ".")
        
        guard components.count == 2 || components.count == 3,
            let headerData = JWTDecoder.data(base64urlEncoded: components[0]),
            let payloadData = JWTDecoder.data(base64urlEncoded: components[1])
        else {
            throw JWTError.invalidJWTString
        }
        
        guard JWT.verify(jwtString, using: verifier) else {
            throw JWTError.failedVerification
        }
        
        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        
        let header = try jsonDecoder.decode(Header.self, from: headerData)
        let payload = try jsonDecoder.decode(T.self, from: payloadData)
        
        self.header = header
        self.payload = payload
    }
    
    /// Sign the JWT using the given algorithm and encode the header, claims and signature as a JWT String.
    ///
    /// - Note: This function will set header.alg field to the name of the signing algorithm.
    ///
    /// - Parameter using algorithm: The algorithm to sign with.
    /// - Returns: A String with the encoded and signed JWT.
    /// - Throws: An EncodingError if the JSONEncoder throws an error while encoding the JWT.
    /// - Throws: `JWTError.osVersionToLow` if not using macOS 10.12.0 (Sierra) or iOS 10.0 or higher.
    /// - Throws: A Signing error if the jwtSigner is unable to sign the JWT with the provided key.
    mutating public func sign(using jwtSigner: JWTSigner) throws -> String {
        var tempHeader = header
        tempHeader.alg = jwtSigner.name
        
        let headerString = try tempHeader.encode()
        let payloadString = try payload.encode()
        
        header.alg = tempHeader.alg
        
        return try jwtSigner.sign(header: headerString, payload: payloadString)
    }

    /// Verify the signature of the encoded JWT using the given algorithm.
    ///
    /// - Parameter jwt: A String with the encoded and signed JWT.
    /// - Parameter using algorithm: The algorithm to verify with.
    /// - Returns: A Bool indicating whether the verification was successful.
    static public func verify(_ jwt: String, using jwtVerifier: JWTVerifier) -> Bool {
        return jwtVerifier.verify(jwt: jwt)
    }

    /// Validate the time based standard JWT claims.
    /// This function checks that the "exp" (expiration time) is in the future
    /// and the "iat" (issued at) and "nbf" (not before) headers are in the past,
    ///
    /// - Parameter leeway: The time in seconds that the JWT can be invalid but still accepted to account for clock differences.
    /// - Returns: A value of `ValidatePayloadResult`.
    public func validatePayload(leeway: TimeInterval = 0) -> ValidatePayloadResult {
        
        guard let expiresAtDate = payload.exp else { fatalError() }
        
        let currentTimestamp = Date()
        
        if currentTimestamp + leeway > expiresAtDate {
            return .expired
        }
        
        return .success
    }
}
