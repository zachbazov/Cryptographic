//
//  VerifierAlgorithm.swift
//  clean-mvvmc-master
//
//  Created by Developer on 22/09/2023.
//

import Foundation

protocol VerifierAlgorithm {
    /// A function to verify the signature of a JSON web token string is correct for the header and claims.
    func verify(jwt: String) -> Bool
}
