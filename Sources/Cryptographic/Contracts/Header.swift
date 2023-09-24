//
//  Header.swift
//  clean-mvvmc-master
//
//  Created by Developer on 21/09/2023.
//

import Foundation

public struct Header: Codable {
    
    /// Type Header Parameter
    public var typ: String?
    /// Algorithm Header Parameter
    public var alg: String?
    /// JSON Web Token Set URL Header Parameter
    public var jku : String?
    /// JSON Web Key Header Parameter
    public var jwk: String?
    /// Key ID Header Parameter
    public var kid: String?
    /// Content Type Header Parameter
    public var cty: String?
    /// Critical Header Parameter
    public var crit: [String]?
    
    /// Initialize a `Header` instance.
    ///
    /// - Parameter typ: The Type Header Parameter
    /// - Parameter jku: The JSON Web Token Set URL Header Parameter
    /// - Parameter jwk: The JSON Web Key Header Parameter
    /// - Parameter kid: The Key ID Header Parameter
    /// - Parameter cty: The Content Type Header Parameter
    /// - Parameter crit: The Critical Header Parameter
    /// - Returns: A new instance of `Header`.
    public init(
        typ: String? = "JWT",
        jku: String? = nil,
        jwk: String? = nil,
        kid: String? = nil,
        cty: String? = nil,
        crit: [String]? = nil
    ) {
        self.typ = typ
        self.alg = nil
        self.jku = jku
        self.jwk = jwk
        self.kid = kid
        self.cty = cty
        self.crit = crit
    }
    
    func encode() throws -> String  {
        let jsonEncoder = JSONEncoder()
        jsonEncoder.dateEncodingStrategy = .secondsSince1970
        
        let data = try jsonEncoder.encode(self)
        
        return JWTEncoder.base64urlEncodedString(data: data)
    }
}
