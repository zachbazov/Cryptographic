//
//  JWTLogger.swift
//  clean-mvvmc-master
//
//  Created by Developer on 22/09/2023.
//

import Foundation
import CodeBureau

public struct JWTLogger {
    
    public func log(issuedAt: TimeInterval, expiresAt: TimeInterval) {
        let currentTimestamp = Date().timeIntervalSince1970
        
        let expirationTimestamp = expiresAt
        
        let remainingTimeInSeconds = Int(expirationTimestamp - currentTimestamp)
        
        let secondsInMinute = 60
        let secondsInHour = 60 * secondsInMinute
        let secondsInDay = 24 * secondsInHour
        
        let remainingDays = remainingTimeInSeconds / secondsInDay
        let remainingHours = (remainingTimeInSeconds % secondsInDay) / secondsInHour
        let remainingMinutes = (remainingTimeInSeconds % secondsInHour) / secondsInMinute
        let remainingSeconds = (remainingTimeInSeconds % secondsInMinute)
        
        let hasNotYetExpired = "JWT expires in \(remainingDays)d, \(remainingHours)h, \(remainingMinutes)m, \(remainingSeconds)s."
        let hasExpired = "JWT expired (\(remainingTimeInSeconds)s) \(remainingDays)d, \(remainingHours)h, \(remainingMinutes)m, \(remainingSeconds)s ago."
        
        let message = remainingTimeInSeconds.description.hasPrefix("-") ? hasExpired : hasNotYetExpired
        
        debugPrint(.debug, message)
    }
}
