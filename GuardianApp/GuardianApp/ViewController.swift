// ViewController.swift
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

class ViewController: UIViewController {

    @IBOutlet var enrollButton: UIButton!
    @IBOutlet var unenrollButton: UIButton!

    @IBOutlet var enrollmentView: UIView!
    @IBOutlet var enrollmentLabel: UILabel!
    @IBOutlet var secretLabel: UILabel!
    @IBOutlet var codeLabel: UILabel!

    /// Refreshes the TOTP code while the screen is visible.
    private var codeTimer: Timer?

    override func viewDidLoad() {
        super.viewDidLoad()
        updateView()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // Scheduled on the main run loop, so the callback runs on the main actor.
        codeTimer?.invalidate()
        codeTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.updateCode() }
        }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        codeTimer?.invalidate()
        codeTimer = nil
    }

    @IBAction func unenrollAction(_ sender: AnyObject) {
        guard let enrollment = AppDelegate.state else { return }
        GuardianService.unenroll(enrollment) { [weak self] result in
            switch result {
            case .failure(let cause):
                self?.offerToForgetLocally(after: cause)
            case .success:
                AppDelegate.state = nil
            }
            self?.updateView()
        }
    }

    /// Unenroll can fail for good, e.g. when the enrollment was already deleted on
    /// the tenant, which would leave the app stuck showing it. Let the user remove
    /// it from this device anyway.
    private func offerToForgetLocally(after cause: Swift.Error) {
        let alert = UIAlertController(
            title: "Unenroll failed",
            message: "\(Self.message(for: cause))\n\nYou can remove the enrollment from this device anyway. "
                + "If it still exists on the tenant, an admin can delete it there.",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Remove from this device", style: .destructive) { [weak self] _ in
            AppDelegate.state = nil
            self?.updateView()
        })
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: nil))
        present(alert, animated: true, completion: nil)
    }

    func updateView() {
        let haveEnrollment = AppDelegate.state != nil
        if let enrollment = AppDelegate.state {
            enrollmentLabel.text = enrollment.identifier
            secretLabel.text = enrollment.otp?.base32Secret
        }
        enrollButton.isHidden = haveEnrollment
        unenrollButton.isHidden = !haveEnrollment
        enrollmentView.isHidden = !haveEnrollment
        updateCode()
    }

    private func updateCode() {
        let code = AppDelegate.state.flatMap(GuardianService.currentCode(for:))
        codeLabel.text = code ?? "No TOTP for this enrollment"
    }

    private func showError(title: String, message: String) {
        let alert = UIAlertController(
            title: title,
            message: message,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .cancel, handler: nil))
        present(alert, animated: true, completion: nil)
    }

    private func showError(title: String, cause: Swift.Error) {
        showError(title: title, message: Self.message(for: cause))
    }

    private static func message(for cause: Swift.Error) -> String {
        (cause as? GuardianError)?.description ?? "Unknown error"
    }

    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        guard
            segue.identifier == "PresentQRCodeReader",
            let qrReaderVC = segue.destination as? QRCodeReaderViewController
        else { return }
        
        qrReaderVC.delegate = self
    }
    
    override func shouldPerformSegue(withIdentifier identifier: String, sender: Any?) -> Bool {
        guard identifier == "PresentQRCodeReader" else { return false }
            
        guard AppDelegate.pushToken != nil else {
            showError(title: "Error", message: "Push token is empty")
            return false
        }
        
        return true
    }
}

extension ViewController: QRCodeReaderViewControllerDelegate {
    func qrCodeViewDidScan(qrCodeValue: String) {
        self.dismiss(animated: true) { [unowned self] in
            self.enroll(usingUri: qrCodeValue)
        }
    }

    func qrCodeViewDidCancel() {
        dismiss(animated: true)
    }

    func qrCodeViewDidFail() {
        // No camera (e.g. the Simulator): let the user paste the enrollment link
        // that the QR code encodes instead.
        dismiss(animated: false) { [weak self] in
            self?.promptForEnrollmentUri()
        }
    }

    private func promptForEnrollmentUri() {
        let alert = UIAlertController(
            title: "Camera unavailable",
            message: "Paste the enrollment link encoded in the QR code",
            preferredStyle: .alert
        )
        alert.addTextField { textField in
            textField.placeholder = "otpauth://..."
            textField.accessibilityIdentifier = "enrollmentUri.textField"
            textField.autocapitalizationType = .none
            textField.autocorrectionType = .no
            textField.keyboardType = .URL
        }
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: nil))
        alert.addAction(UIAlertAction(title: "Enroll", style: .default) { [unowned self, unowned alert] _ in
            guard let uri = alert.textFields?.first?.text?.trimmingCharacters(in: .whitespacesAndNewlines), !uri.isEmpty else {
                return self.showError(title: "Error", message: "Enrollment link is empty")
            }
            self.enroll(usingUri: uri)
        })
        present(alert, animated: true, completion: nil)
    }

    private func enroll(usingUri enrollmentUri: String) {
        guard let notificationToken = AppDelegate.pushToken else {
            return showError(title: "Error", message: "Push token is empty")
        }
        GuardianService.enroll(usingUri: enrollmentUri, notificationToken: notificationToken) { [weak self] result in
            switch result {
            case .failure(let cause):
                self?.showError(title: "Enroll failed", cause: cause)
            case .success(let enrollment):
                AppDelegate.state = enrollment
            }
            self?.updateView()
        }
    }
}
