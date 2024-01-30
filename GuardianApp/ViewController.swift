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

    private static let RSA_KEY_PUBLIC_TAG = "PUBLIC_TAG"
    private static let RSA_KEY_PRIVATE_TAG = "PRIVATE_TAG"

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
                .api(forDomain: AppDelegate.guardianDomain)
                .device(forEnrollmentId: enrollment.identifier, userId: enrollment.userId, signingKey: enrollment.signingKey)
                .delete()
            debugPrint(request)
            request.start { [unowned self] result in
                    switch result {
                    case .failure(let cause):
                        self.showError(title: "Unenroll failed", cause: cause)
                    case .success:
                        AppDelegate.state = nil
                    }
                    self.updateView()
            }
        }
    }

    func updateView() {
        DispatchQueue.main.async { [unowned self] in
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
        DispatchQueue.main.async { [unowned self] in
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
        print("QR scanned with result:\n\(qrCodeValue)")
        self.dismiss(animated: true) { [unowned self] in

            guard let signingKey = try? KeychainRSAPrivateKey.new(with: ViewController.RSA_KEY_PRIVATE_TAG),
                let verificationKey = try? signingKey.verificationKey() else { return }

            let request = Guardian.enroll(
                forDomain: AppDelegate.guardianDomain,
                usingUri: qrCodeValue,
                notificationToken: AppDelegate.pushToken!,
                signingKey: signingKey,
                verificationKey: verificationKey)
            
            debugPrint(request)
            request
                .on(response: { event in
                    guard let data = event.data else { return }
                    let body = String(data: data, encoding: .utf8) ?? "INVALID BODY"
                    print(body)
                })
                .start { result in
                    switch result {
                    case .failure(let cause):
                        self.showError(title: "Enroll failed", cause: cause)
                    case .success(let enrollment):
                        AppDelegate.state = GuardianState(identifier: enrollment.id, localIdentifier: enrollment.localIdentifier, keyTag: signingKey.tag, otp: enrollment.totp, userId: enrollment.userId)
                    }
                    self.updateView()
            }
        }
    }
    
    func qrCodeViewDidCancel() {
        dismiss(animated: true)
    }
    
    func qrCodeViewDidFail() {
        dismiss(animated: false) { [weak self] in
            self?.showError(title: "Error", message: "Camera usage not supported by the current device")
        }
    }
}
