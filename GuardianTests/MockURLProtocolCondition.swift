//
//  MockURLProtocolCondition.swift
//  GuardianTests
//
//  Created by Artem Bakanov on 18/02/2024.
//  Copyright © 2024 Auth0. All rights reserved.
//

import Foundation

typealias MockURLProtocolCondition = (URLRequest) -> Bool

func &&(lhs: @escaping MockURLProtocolCondition, rhs: @escaping MockURLProtocolCondition) -> MockURLProtocolCondition {
    { request in
        lhs(request) && rhs(request)
    }
}

prefix func !(rhs: @escaping MockURLProtocolCondition) -> MockURLProtocolCondition {
    { request in
        !rhs(request)
    }
}
