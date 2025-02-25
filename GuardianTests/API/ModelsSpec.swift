// ModelsSpec.swift
//
// Copyright (c) 2025 Auth0 (http://auth0.com)
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

class ModelsSpec: QuickSpec {
    override class func spec() {
        describe("Decodable") {
            it("should load from Json decoder") {
                let jsonData = "{\"audience\":\"my_audience\",\"scope\":[\"openid\",\"my_scope\"],\"binding_message\":\"my_binding_message\"}";
                let result = try? JSONDecoder().decode(ConsentRequestedDetailsEntity.self, from: jsonData.data(using: .utf8)!);
                expect(result).toNot(beNil())
                expect(result?.audience).to(equal("my_audience"))
                expect(result?.bindingMessage).to(equal("my_binding_message"))
                expect(result?.scope).to(contain(["openid", "my_scope"]))
                expect(result?.authorizationDetails).to(beEmpty())
            }
            
            it("should load from Json decoder with authorization_details") {
                let jsonData = "{\"audience\":\"my_audience\",\"scope\":[\"openid\",\"my_scope\"],\"binding_message\":\"my_binding_message\",\"authorization_details\":[{\"type\":\"account_information\",\"actions\":[\"list_accounts\",\"read_balances\",\"read_transactions\"],\"locations\":[\"https://example.com/accounts\"]},{\"type\":\"payment_initiation\",\"actions\":[\"initiate\",\"status\",\"cancel\"],\"locations\":[\"https://example.com/payments\"],\"instructedAmount\":{\"currency\":\"EUR\",\"amount\":123.50},\"creditorName\":\"Merchant123\",\"creditorAccount\":{\"iban\":\"DE02100100109307118603\"},\"remittanceInformationUnstructured\":\"Ref Number Merchant\"}]}";
                
                let result = try? JSONDecoder().decode(ConsentRequestedDetailsEntity.self, from: jsonData.data(using: .utf8)!);
                expect(result).toNot(beNil())
                expect(result!.audience).to(equal("my_audience"))
                expect(result!.bindingMessage).to(equal("my_binding_message"))
                expect(result!.scope).to(contain(["openid", "my_scope"]))
                expect(result!.authorizationDetails).toNot(beEmpty())
                
                let accountInfoJson = (result!.authorizationDetails.first)!
                expect(accountInfoJson["type"]?.stringValue).to(equal("account_information"))
                expect(accountInfoJson["actions"]?.arrayValue?.map{ $0.stringValue! }).to(contain("list_accounts", "read_balances", "read_transactions"))
                expect(accountInfoJson["locations"]?.arrayValue?.map{ $0.stringValue! }).to(contain("https://example.com/accounts"))
                
                let paymentInitiationJson = (result!.authorizationDetails.last)!
                expect(paymentInitiationJson["type"]?.stringValue).to(equal("payment_initiation"))
                expect(paymentInitiationJson["actions"]?.arrayValue?.map{ $0.stringValue! }).to(contain("initiate", "status", "cancel"))
                expect(paymentInitiationJson["locations"]?.arrayValue?.map{ $0.stringValue! }).to(contain("https://example.com/payments"))
                expect(paymentInitiationJson["instructedAmount"]?["currency"]?.stringValue).to(equal("EUR"))
                expect(paymentInitiationJson["instructedAmount"]?["amount"]?.doubleValue).to(equal(123.50))
                expect(paymentInitiationJson["creditorName"]?.stringValue).to(equal("Merchant123"))
                expect(paymentInitiationJson["creditorAccount"]?["iban"]?.stringValue).to(equal("DE02100100109307118603"))
                expect(paymentInitiationJson["remittanceInformationUnstructured"]?.stringValue).to(equal("Ref Number Merchant"))
                
                let accountInfo : [AccountInfo] = result!.authorizationDetails("account_information")
                expect(accountInfo.count).to(equal(1))
                expect(accountInfo).to(contain(
                    AccountInfo(
                        type: "account_information",
                        actions: ["list_accounts", "read_balances", "read_transactions"],
                        locations: ["https://example.com/accounts"]
                    )
                ))
                
                
                let paymentInitiation : [PaymentInitiation] = result!.authorizationDetails("payment_initiation")
                expect(paymentInitiation.count).to(equal(1))
                expect(paymentInitiation).to(contain(
                    PaymentInitiation(
                        type: "payment_initiation",
                        actions: ["initiate", "status", "cancel"],
                        locations: ["https://example.com/payments"],
                        instructedAmount: Money(amount: 123.50, currency: "EUR"),
                        creditorName: "Merchant123",
                        creditorAccount: BankAccount(iban: "DE02100100109307118603"),
                        remittanceInformationUnstructured: "Ref Number Merchant"
                    )
                ))
            }
        }
    }
    
    struct AccountInfo : Equatable, Codable {
        let type: String;
        let actions: [String];
        let locations: [String];
    }
    
    struct PaymentInitiation : Equatable, Codable {
        let type: String;
        let actions: [String];
        let locations: [String];
        let instructedAmount: Money;
        let creditorName: String;
        let creditorAccount: BankAccount;
        let remittanceInformationUnstructured: String;
    }
    
    struct Money : Equatable, Codable {
        let amount: Decimal;
        let currency: String;
    }
    
    struct BankAccount : Equatable, Codable {
        let iban: String;
    }
}
