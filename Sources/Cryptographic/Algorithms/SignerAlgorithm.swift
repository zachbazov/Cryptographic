//
//  SignerAlgorithm.swift
//  clean-mvvmc-master
//
//  Created by Developer on 22/09/2023.
//

import Foundation

protocol SignerAlgorithm {
    /// A function to sign the header and claims of a JSON web token and return a signed JWT string.
    func sign(header: String, payload: String) throws -> String
}
