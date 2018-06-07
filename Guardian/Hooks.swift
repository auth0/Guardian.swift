//
//  Hooks.swift
//  Guardian
//
//  Created by Hernan Zalazar on 07/06/2018.
//  Copyright © 2018 Auth0. All rights reserved.
//

import Foundation

/// Hook that will be called before request is sent
public typealias RequestHook = (URLRequest) -> ()
/// Hook that will be called when a response is received (any status code) along with data (if any)
public typealias ResponseHook = (HTTPURLResponse, Data?) -> ()
/// Hook that will be called when request fails with error
public typealias ErrorHook = (Error) -> ()

struct Hooks {
    let request: RequestHook?
    let response: ResponseHook?
    let error: ErrorHook?

    init(request: RequestHook? = nil, response: ResponseHook? = nil, error: ErrorHook? = nil) {
        self.request = request
        self.response = response
        self.error = error
    }
}
