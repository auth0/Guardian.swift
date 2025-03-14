// NotificationController.swift
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

import UIKit
import Guardian

class NotificationController: UIViewController {

    var notification: Guardian.Notification? = nil

    @IBOutlet var browserLabel: UILabel!
    @IBOutlet var locationLabel: UILabel!
    @IBOutlet var dateLabel: UILabel!
    
    @IBOutlet var denyButton: UIButton!
    @IBOutlet var allowButton: UIButton!
    
    @IBOutlet var consentDetailsView: UIStackView!
    @IBOutlet var bindingMessageLabel: UILabel!
    
    @IBAction func allowAction(_ sender: AnyObject) {
        guard let notification = notification, let enrollment = AppDelegate.state else {
            return self.dismiss(animated: true, completion: nil)
        }
        let request = Guardian
            .authentication(forDomain: AppDelegate.tenantDomain, device: enrollment)
            .allow(notification: notification)
        debugPrint(request)
        request.start { result in
                print(result)
                switch result {
                case .success:
                    DispatchQueue.main.async { [unowned self] in
                        self.dismiss(animated: true, completion: nil)
                    }
                case .failure(let cause):
                    self.showError("Allow failed", cause)
                }
        }
    }

    @IBAction func denyAction(_ sender: AnyObject) {
        guard let notification = notification, let enrollment = AppDelegate.state else {
            return self.dismiss(animated: true, completion: nil)
        }
        let request = Guardian
            .authentication(forDomain: AppDelegate.tenantDomain, device: enrollment)
            .reject(notification: notification)
        debugPrint(request)
        request.start { result in
                print(result)
                switch result {
                case .success:
                    DispatchQueue.main.async { [unowned self] in
                        self.dismiss(animated: true, completion: nil)
                    }
                case .failure(let cause):
                    self.showError("Reject failed", cause)
                }
        }
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        guard let notification = notification, let enrollment = AppDelegate.state else {
            return
        }

        browserLabel.text = notification.source?.browser?.name ?? "Unknown"
        locationLabel.text = notification.location?.name ?? "Unknown"
        dateLabel.text = "\(notification.startedAt)"
        self.consentDetailsView.isHidden = true
        
        guard let consentId = notification.transactionLinkingId else {
            return
        }
        
        denyButton.isHidden = true
        allowButton.isHidden = true
        
        Guardian
            .consent(forDomain: AppDelegate.tenantDomain)
            .fetch(consentId: consentId, transactionToken: notification.transactionToken, signingKey: enrollment.signingKey)
            .start{ [unowned self] result in
                switch result {
                case .failure(let cause):
                    print("Fetch consent failed: \(cause)")
                case .success(let payload):
                    showRichConsent(requestedDetails: payload.requestedDetails)
            }
        }
    }
    
    func showRichConsent(requestedDetails: ConsentRequestedDetails) {
        DispatchQueue.main.async { [unowned self] in
            if !requestedDetails.authorizationDetails.isEmpty {
                let authDetailsView = showAuthorizationDetails(requestedDetails: requestedDetails)
                self.consentDetailsView.addArrangedSubview(authDetailsView)
            }
            
            self.denyButton.isHidden = false
            self.allowButton.isHidden = false
            self.consentDetailsView.isHidden = false
            self.bindingMessageLabel.text = requestedDetails.bindingMessage
        }
    }
    
    func showAuthorizationDetails(requestedDetails: ConsentRequestedDetails) -> UIView {
        let paymentInitiation = requestedDetails.filterAuthorizationDetailsByType(PaymentInitiation.self)
        
        return !paymentInitiation.isEmpty
        ? PaymentInitiationView(fromPaymentInitiation: paymentInitiation.first!)
        : DynamicAuthorizationDetailsView(fromAuthorizationDetails: requestedDetails.authorizationDetails)
    }

    func showError(_ title: String, _ cause: Swift.Error) {
        DispatchQueue.main.async { [unowned self] in
            var errorMessage = "Unknown error"
            if let cause = cause as? GuardianError {
                errorMessage = cause.description
            }
            let alert = UIAlertController(
                title: title,
                message: errorMessage,
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: "OK", style: .cancel, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
    }
}
