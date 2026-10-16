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
import Guardian

class ViewController: UIViewController {

    @IBOutlet var enrollButton: UIButton!
    @IBOutlet var unenrollButton: UIButton!

    @IBOutlet var enrollmentView: UIView!
    @IBOutlet var enrollmentLabel: UILabel!
    @IBOutlet var secretLabel: UILabel!

    override func viewDidLoad() {
        super.viewDidLoad()
        updateView()
    }

    @IBAction func unenrollAction(_ sender: AnyObject) {
        if let enrollment = AppDelegate.state {
            let request = Guardian
                .api(forDomain: AppDelegate.tenantDomain)
                .device(forEnrollmentId: enrollment.identifier, userId: enrollment.userId, signingKey: enrollment.signingKey)
                .delete()
            request.start { [weak self] result in
                    switch result {
                    case .failure(let cause):
                        self?.showError(title: "Unenroll failed", cause: cause)
                    case .success:
                        AppDelegate.state = nil
                    }
                    self?.updateView()
            }
        }
    }

    func updateView() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let haveEnrollment = AppDelegate.state != nil
            if let enrollment = AppDelegate.state {
                self.enrollmentLabel.text = enrollment.identifier
                self.secretLabel.text = enrollment.otp?.base32Secret
            }
            self.enrollButton.isHidden = haveEnrollment
            self.unenrollButton.isHidden = !haveEnrollment
            self.enrollmentView.isHidden = !haveEnrollment
        }
    }
    
    private func showError(title: String, message: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let alert = UIAlertController(
                title: title,
                message: message,
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: "OK", style: .cancel, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
    }

    private func showError(title: String, cause: Swift.Error) {
        var errorMessage = "Unknown error"
        if let cause = cause as? GuardianError {
            errorMessage = cause.description
        }
        showError(title: title, message: errorMessage)
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
        // Each enrollment gets its own signing key. new(with:) returns the key
        // already stored under a tag, so a fixed tag would share one key across
        // enrollments.
        let keyTag = "com.auth0.guardian.sample.signing-key.\(UUID().uuidString)"
        guard let signingKey = try? KeychainRSAPrivateKey.new(with: keyTag),
            let verificationKey = try? signingKey.verificationKey() else {
            GuardianState.deleteSigningKey(withTag: keyTag)
            return showError(title: "Error", message: "Could not create the device signing key")
        }

        let request = Guardian.enroll(
            forDomain: AppDelegate.tenantDomain,
            usingUri: enrollmentUri,
            notificationToken: notificationToken,
            signingKey: signingKey,
            verificationKey: verificationKey)

        request
            .on(response: { event in
                // Log the status only: the response body carries the TOTP secret.
                #if DEBUG
                print("Enroll response: HTTP \(event.response.statusCode)")
                #endif
            })
            .start { result in
                switch result {
                case .failure(let cause):
                    GuardianState.deleteSigningKey(withTag: keyTag)
                    self.showError(title: "Enroll failed", cause: cause)
                case .success(let enrollment):
                    AppDelegate.state = GuardianState(identifier: enrollment.id, localIdentifier: enrollment.localIdentifier, signingKey: signingKey, otp: enrollment.totp, userId: enrollment.userId)
                }
                self.updateView()
        }
    }
}
