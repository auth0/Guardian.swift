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
import AVFoundation
import Guardian
import QRCodeReader

class ViewController: UIViewController, QRCodeReaderViewControllerDelegate {

    private static let RSA_KEY_PUBLIC_TAG = "PUBLIC_TAG"
    private static let RSA_KEY_PRIVATE_TAG = "PRIVATE_TAG"

    @IBOutlet var enrollButton: UIButton!
    @IBOutlet var unenrollButton: UIButton!

    @IBOutlet var enrollmentView: UIView!
    @IBOutlet var enrollmentLabel: UILabel!
    @IBOutlet var secretLabel: UILabel!

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.

        updateView()
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    @IBAction func scanAction(_ sender: AnyObject) {
        if let _ = AppDelegate.pushToken {
            if let supports = try? QRCodeReader.supportsMetadataObjectTypes(), supports {
                let reader = createReader()
                reader.modalPresentationStyle = .formSheet
                reader.delegate               = self

                reader.completionBlock = { (result: QRCodeReaderResult?) in
                    if let result = result {
                        print("Completion with result: \(result.value) of type \(result.metadataType)")
                    }
                }

                present(reader, animated: true, completion: nil)
            } else {
                let alert = UIAlertController(title: "Error", message: "Reader not supported by the current device", preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "OK", style: .cancel, handler: nil))
                
                present(alert, animated: true, completion: nil)
            }
        }
    }

    // MARK: - QRCodeReader Delegate Methods
    func reader(_ reader: QRCodeReaderViewController, didScanResult result: QRCodeReaderResult) {
        self.dismiss(animated: true) { [unowned self] in

            guard let signingKey = try? KeychainRSAPrivateKey.new(with: ViewController.RSA_KEY_PRIVATE_TAG),
                let verificationKey = try? signingKey.verificationKey() else { return }

            let request = Guardian
                .enroll(forDomain: AppDelegate.guardianDomain, usingUri: result.value, notificationToken: AppDelegate.pushToken!, signingKey: signingKey, verificationKey: verificationKey)
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
                        self.showError("Enroll failed", cause)
                    case .success(let enrollment):
                        AppDelegate.state = GuardianState(identifier: enrollment.id, localIdentifier: enrollment.localIdentifier, keyTag: signingKey.tag, otp: enrollment.totp, userId: enrollment.userId)
                    }
                    self.updateView()
            }
        }
    }

    func readerDidCancel(_ reader: QRCodeReaderViewController) {
        self.dismiss(animated: true, completion: nil)
    }

    fileprivate func createReader() -> QRCodeReaderViewController {
        let builder = QRCodeReaderViewControllerBuilder { builder in
            builder.reader = QRCodeReader(metadataObjectTypes: [AVMetadataObject.ObjectType.qr])
            builder.showSwitchCameraButton = false
            builder.showTorchButton = false
            builder.showCancelButton = true
        }
        
        return QRCodeReaderViewController(builder: builder)
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
                        self.showError("Unenroll failed", cause)
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

