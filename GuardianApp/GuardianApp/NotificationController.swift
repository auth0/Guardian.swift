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
@preconcurrency import Guardian

class NotificationController: UIViewController {

    var notification: Guardian.Notification? = nil

    @IBOutlet var browserLabel: UILabel!
    @IBOutlet var locationLabel: UILabel!
    @IBOutlet var dateLabel: UILabel!
    
    @IBOutlet var denyButton: UIButton!
    @IBOutlet var allowButton: UIButton!
    
    @IBOutlet var consentDetailsView: UIStackView!
    @IBOutlet var bindingMessageView: UIStackView!
    @IBOutlet var bindingMessageLabel: UILabel!
    
    @IBAction func allowAction(_ sender: AnyObject) {
        guard let notification = notification, let enrollment = AppDelegate.state else {
            return dismiss(animated: true, completion: nil)
        }
        GuardianService.allow(notification, device: enrollment) { [weak self] result in
            switch result {
            case .success:
                self?.dismiss(animated: true, completion: nil)
            case .failure(let cause):
                self?.showError("Allow failed", cause)
            }
        }
    }

    @IBAction func denyAction(_ sender: AnyObject) {
        guard let notification = notification, let enrollment = AppDelegate.state else {
            return dismiss(animated: true, completion: nil)
        }
        GuardianService.reject(notification, device: enrollment) { [weak self] result in
            switch result {
            case .success:
                self?.dismiss(animated: true, completion: nil)
            case .failure(let cause):
                self?.showError("Reject failed", cause)
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
        consentDetailsView.isHidden = true
        bindingMessageView.isHidden = true
        
        guard let consentId = notification.transactionLinkingId else {
            return
        }
        
        denyButton.isHidden = true
        allowButton.isHidden = true
        
        GuardianService.fetchConsentDetails(consentId: consentId, notification: notification, device: enrollment) { [weak self] result in
            switch result {
            case .failure(let cause):
                self?.showConsentFailure(cause)
            case .success(let requestedDetails):
                self?.showRichConsent(requestedDetails: requestedDetails)
            }
        }
    }

    func showRichConsent(requestedDetails: ConsentRequestedDetails) {
        if !requestedDetails.authorizationDetails.isEmpty {
            let authDetailsView = showAuthorizationDetails(requestedDetails: requestedDetails)
            consentDetailsView.addArrangedSubview(authDetailsView)
        }

        if requestedDetails.bindingMessage != nil {
            bindingMessageLabel.text = requestedDetails.bindingMessage
            bindingMessageView.isHidden = false
        }

        denyButton.isHidden = false
        allowButton.isHidden = false
        consentDetailsView.isHidden = false
    }
    
    /// Without the consent details the user can't see what they would approve,
    /// so offer Deny or Close, but never Allow.
    func showConsentFailure(_ cause: Swift.Error) {
        denyButton.isHidden = false
        let alert = UIAlertController(
            title: "Couldn't load the request details",
            message: "\(Self.message(for: cause))\n\nYou can deny this request or close it.",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Deny", style: .destructive) { [weak self] _ in
            self?.denyAction(alert)
        })
        alert.addAction(UIAlertAction(title: "Close", style: .cancel) { [weak self] _ in
            self?.dismiss(animated: true, completion: nil)
        })
        present(alert, animated: true, completion: nil)
    }

    func showAuthorizationDetails(requestedDetails: ConsentRequestedDetails) -> UIView {
        if let paymentInitiation = requestedDetails.filterAuthorizationDetailsByType(PaymentInitiation.self).first {
            return PaymentInitiationView(fromPaymentInitiation: paymentInitiation)
        }
        return DynamicAuthorizationDetailsView(fromAuthorizationDetails: requestedDetails.authorizationDetails)
    }

    func showError(_ title: String, _ cause: Swift.Error) {
        let alert = UIAlertController(
            title: title,
            message: Self.message(for: cause),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .cancel, handler: nil))
        present(alert, animated: true, completion: nil)
    }

    private static func message(for cause: Swift.Error) -> String {
        return (cause as? GuardianError)?.description ?? "Unknown error"
    }
}
