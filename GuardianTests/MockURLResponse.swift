//
//  MockURLResopnse.swift
//  GuardianTests
//
//  Created by Artem Bakanov on 18/02/2024.
//  Copyright © 2024 Auth0. All rights reserved.
//

import Foundation

class MockURLResponse {
    let statusCode: Int
    let headers: [String : String]?
    let jsonObject: [String : Any]?
    
    init(jsonObject: [String : Any]?, statusCode: Int, headers: [String : String]?) {
        self.statusCode = statusCode
        self.jsonObject = jsonObject
        self.headers = headers
    }
    
    func httpResponse(url: URL) -> HTTPURLResponse? {
        HTTPURLResponse(url: url, statusCode: statusCode, httpVersion: "HTTP/1.1", headerFields: headers)
    }
    
    var data: Data? {
        guard let jsonObject else { return nil }
        return try? JSONSerialization.data(withJSONObject: jsonObject)
    }
}
