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

class ViewController: UIViewController, QRCodeReaderViewControllerDelegate {

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

    @IBAction func scanAction(sender: AnyObject) {
        if let _ = AppDelegate.pushToken {
            if QRCodeReader.supportsMetadataObjectTypes() {
                let reader = createReader()
                reader.modalPresentationStyle = .FormSheet
                reader.delegate               = self

                reader.completionBlock = { (result: QRCodeReaderResult?) in
                    if let result = result {
                        print("Completion with result: \(result.value) of type \(result.metadataType)")
                    }
                }

                presentViewController(reader, animated: true, completion: nil)
            } else {
                let alert = UIAlertController(title: "Error", message: "Reader not supported by the current device", preferredStyle: .Alert)
                alert.addAction(UIAlertAction(title: "OK", style: .Cancel, handler: nil))
                
                presentViewController(alert, animated: true, completion: nil)
            }
        }
    }

    // MARK: - QRCodeReader Delegate Methods
    func reader(reader: QRCodeReaderViewController, didScanResult result: QRCodeReaderResult) {
        self.dismissViewControllerAnimated(true) { [unowned self] in

                Guardian
                    .enroll(forDomain: AppDelegate.guardianDomain, usingUri: result.value, notificationToken: AppDelegate.pushToken!)
                    .start { result in
                        switch result {
                        case .Failure(let cause):
                            self.showError("Enroll failed", cause)
                        case .Success(let enrollment):
                            AppDelegate.enrollment = enrollment
                        }
                        self.updateView()
                }
        }
    }

    func readerDidCancel(reader: QRCodeReaderViewController) {
        self.dismissViewControllerAnimated(true, completion: nil)
    }

    private func createReader() -> QRCodeReaderViewController {
        let builder = QRCodeViewControllerBuilder { builder in
            builder.reader = QRCodeReader(metadataObjectTypes: [AVMetadataObjectTypeQRCode])
            builder.showSwitchCameraButton = false
            builder.showTorchButton = false
            builder.showCancelButton = true
        }
        
        return QRCodeReaderViewController(builder: builder)
    }

    @IBAction func unenrollAction(sender: AnyObject) {
        if let enrollment = AppDelegate.enrollment {
            Guardian
                .api(forDomain: AppDelegate.guardianDomain)
                .device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
                .delete()
                .start { [unowned self] result in
                    switch result {
                    case .Failure(let cause):
                        self.showError("Unenroll failed", cause)
                    case .Success(payload: _):
                        AppDelegate.enrollment = nil
                    }
                    self.updateView()
            }
        }
    }

    func updateView() {
        dispatch_async(dispatch_get_main_queue()) { [unowned self] in
            let haveEnrollment = AppDelegate.enrollment != nil
            if let enrollment = AppDelegate.enrollment {
                self.enrollmentLabel.text = enrollment.id
                self.secretLabel.text = enrollment.base32Secret
            }
            self.enrollButton.hidden = haveEnrollment
            self.unenrollButton.hidden = !haveEnrollment
            self.enrollmentView.hidden = !haveEnrollment
        }
    }

    func showError(title: String, _ cause: ErrorType) {
        dispatch_async(dispatch_get_main_queue()) { [unowned self] in
            var errorMessage = "Unknown error"
            if let cause = cause as? GuardianError {
                errorMessage = cause.description
            }
            let alert = UIAlertController(
                title: title,
                message: errorMessage,
                preferredStyle: .Alert
            )
            alert.addAction(UIAlertAction(title: "OK", style: .Cancel, handler: nil))
            self.presentViewController(alert, animated: true, completion: nil)
        }
    }
}

