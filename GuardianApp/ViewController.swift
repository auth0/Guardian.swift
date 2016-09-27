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

    let guardian = Guardian(baseUrl: NSURL(string: "https://nikolaseu-test.guardian.auth0.com")!)

    var enrollment: Enrollment? = nil

    @IBOutlet var enrollButton: UIButton?
    @IBOutlet var unenrollButton: UIButton?
    @IBOutlet var enrollmentTextView: UITextView?

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

    // MARK: - QRCodeReader Delegate Methods
    func reader(reader: QRCodeReaderViewController, didScanResult result: QRCodeReaderResult) {
        self.dismissViewControllerAnimated(true) { [weak self] in
            self?.guardian
                .enroll(withURI: result.value, notificationToken: "1234567890123456789012345678901234567890123456789012345678901234")
                .start { result in
                    switch result {
                    case .Failure(let cause):
                        var errorMessage = "Unknown error"
                        if let cause = cause as? GuardianError {
                            errorMessage = cause.description
                        }
                        let alert = UIAlertController(
                            title: "Enroll failed",
                            message: errorMessage,
                            preferredStyle: .Alert
                        )
                        alert.addAction(UIAlertAction(title: "OK", style: .Cancel, handler: nil))

                        self?.presentViewController(alert, animated: true, completion: nil)
                    case .Success(let enrollment):
                        self?.enrollment = enrollment
                    }
                    self?.updateView()
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
        if let enrollment = enrollment {
            self.guardian
            .delete(enrollment: enrollment)
                .start { [weak self] result in
                    switch result {
                    case .Failure(let cause):
                        var errorMessage = "Unknown error"
                        if let cause = cause as? GuardianError {
                            errorMessage = cause.description
                        }
                        let alert = UIAlertController(
                            title: "Unenroll failed",
                            message: errorMessage,
                            preferredStyle: .Alert
                        )
                        alert.addAction(UIAlertAction(title: "OK", style: .Cancel, handler: nil))
                        self?.presentViewController(alert, animated: true, completion: nil)
                    case .Success(payload: _):
                        self?.enrollment = nil
                    }
                    self?.updateView()
            }
        }
    }

    func updateView() {
        dispatch_async(dispatch_get_main_queue()) { [weak self] in
            let haveEnrollment = self?.enrollment != nil
            if let enrollment = self?.enrollment {
                self?.enrollmentTextView?.text =
                    "Issuer: \(enrollment.issuer)\n" +
                    "User: \(enrollment.user)\n" +
                    "Enrollment id: \(enrollment.id)\n"
            }
            self?.enrollButton?.hidden = haveEnrollment
            self?.unenrollButton?.hidden = !haveEnrollment
            self?.enrollmentTextView?.hidden = !haveEnrollment
        }
    }
}

