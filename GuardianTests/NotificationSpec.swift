// NotificationSpec.swift
//
// Copyright (c) 2016 Auth0 (http://auth0.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import Quick
import Nimble

@testable import Guardian

class NotificationSpec: QuickSpec {
    override func spec() {

        describe("init") {

            context("valid payload") {
                let notification = AuthenticationNotification(userInfo: payload())

                it("should build with valid payload") {
                    expect(notification).toNot(beNil())
                }

                it("should have source") {
                    expect(notification?.source).toNot(beNil())
                    expect(notification?.source?.browser?.name).to(equal("Safari"))
                    expect(notification?.source?.browser?.version).to(equal("9.0.3"))
                    expect(notification?.source?.os?.name).to(equal("Mac OS"))
                    expect(notification?.source?.os?.version).to(equal("10.11.3"))
                }

                it("should have account id") {
                    expect(notification?.enrollmentId).to(equal("dev_VJGBI87d093cnl03"))
                }

                it("should have domain") {
                    expect(notification?.domain).to(equal("samples.auth0.com"))
                }

                it("should have tx id") {
                    expect(notification?.transactionToken).to(equal("random_tx_token"))
                }

                it("should have location name") {
                    expect(notification?.location?.name).to(equal("Palermo, BA, Argentina"))
                }

                it("should have latitude") {
                    expect(notification?.location?.latitude).to(equal(-34.57115))
                }

                it("should have longitude") {
                    expect(notification?.location?.longitude).to(equal(-58.423297))
                }

                it("should have started at date") {
                    expect(notification?.startedAt).to(equal(Date(timeIntervalSince1970: 1450382011)))
                }
            }

            context("source handling") {
                let browser = "Safari"
                let os = "OS X El Capitán"

                var notification: Guardian.Notification!

                it("should include full source") {
                    notification = AuthenticationNotification(userInfo: payload(browser: browser, os: os))
                    expect(notification.source).toNot(beNil())
                }

                it("should include only browser") {
                    notification = AuthenticationNotification(userInfo: payload(browser: browser, os: nil))
                    expect(notification.source).toNot(beNil())
                }

                it("should include only os") {
                    notification = AuthenticationNotification(userInfo: payload(browser: nil, os: os))
                    expect(notification.source).toNot(beNil())
                }

                it("should return nothing when missing source") {
                    notification = AuthenticationNotification(userInfo: payload(browser: nil, os: nil))
                    expect(notification.source).to(beNil())
                }
            }

            context("missing attributes") {

                var notification: Guardian.Notification!

                it("should fail with empty payload") {
                    notification = AuthenticationNotification(userInfo: [:])
                    expect(notification).to(beNil())
                }

                it("should not fail without source") {
                    notification = AuthenticationNotification(userInfo: payload(browser: nil, os: nil))
                    expect(notification).toNot(beNil())
                }

                it("should fail without domain") {
                    notification = AuthenticationNotification(userInfo: payload(host: nil))
                    expect(notification).to(beNil())
                }

                it("should fail without account id") {
                    notification = AuthenticationNotification(userInfo: payload(device: nil))
                    expect(notification).to(beNil())
                }

                it("should fail without tx id") {
                    notification = AuthenticationNotification(userInfo: payload(token: nil))
                    expect(notification).to(beNil())
                }

                it("should fail without started at") {
                    notification = AuthenticationNotification(userInfo: payload(startedAt: nil))
                    expect(notification).to(beNil())
                }

                it("should fail if notification category is invalid") {
                    notification = AuthenticationNotification(userInfo: payload(category: "some other category"))
                    expect(notification).to(beNil())
                }
            }
        }
    }
}

func payload(
             category: String = "com.auth0.notification.authentication",
             device: String? = "dev_VJGBI87d093cnl03",
             browser: String? = "Safari",
             browserVersion: String? = "9.0.3",
             os: String? = "Mac OS",
             osVersion: String? = "10.11.3",
             token: String? = "random_tx_token",
             startedAt: String? = "2015-12-17T19:53:31.000Z",
             host: String? = "samples.auth0.com",
             latitude: String? = "-34.57115",
             longitude: String? = "-58.423297",
             locationName: String? = "Palermo, BA, Argentina") -> [String: Any] {
    var payload: [String: [String: Any]] = [
        "aps": [
            "alert" : [
                "body" : "Login with p@p.xom in login0",
                "title" : "login0:authentication"
            ],
            "category" : category
        ],
        "mfa": [:]
    ]

    if device != nil {
        payload["mfa"]!["dai"] = device
    }
    if token != nil {
        payload["mfa"]!["txtkn"] = token
    }
    if startedAt != nil {
        payload["mfa"]!["d"] = startedAt
    }
    if host != nil {
        payload["mfa"]!["sh"] = host
    }

    var source = [String: [String: String]]()
    if browser != nil && browserVersion != nil {
        source["b"] = [
            "n": browser!,
            "v": browserVersion!
        ]
    } else if browser != nil {
        source["b"] = [
            "n": browser!,
        ]
    }
    if os != nil && osVersion != nil{
        source["os"] = [
            "n": os!,
            "v": osVersion!
        ]
    } else if os != nil {
        source["os"] = [
            "n": os!,
        ]
    }
    if !source.isEmpty {
        payload["mfa"]!["s"] = source
    }

    var location = [String: String]()
    if latitude != nil {
        location["lat"] = latitude
    }
    if longitude != nil {
        location["long"] = longitude
    }
    if locationName != nil {
        location["n"] = locationName
    }
    if !source.isEmpty {
        payload["mfa"]!["l"] = location
    }

    return payload
}

