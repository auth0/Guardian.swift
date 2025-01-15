//  QRCodeReaderViewController.swift
//
// Copyright (c) 2018 Auth0 (http://auth0.com)
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

protocol QRCodeReaderViewControllerDelegate: AnyObject {
    func qrCodeViewDidScan(qrCodeValue: String)
    func qrCodeViewDidCancel()
    func qrCodeViewDidFail()
}

class QRCodeReaderViewController: UIViewController {
    private var captureSession: AVCaptureSession?
    private var previewLayer: CALayer!
    
    @IBOutlet var cameraView: UIView!
    @IBOutlet var frameView: UIView!
    
    weak var delegate: QRCodeReaderViewControllerDelegate?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        let captureSession = AVCaptureSession()
        let previewLayer = AVCaptureVideoPreviewLayer(session: captureSession)
        let metadataOutput = AVCaptureMetadataOutput()
        
        guard
            let videoCaptureDevice = AVCaptureDevice.default(for: .video),
            let videoInput = try? AVCaptureDeviceInput(device: videoCaptureDevice),
            captureSession.canAddInput(videoInput),
            captureSession.canAddOutput(metadataOutput)
        else {
            return
        }
        
        captureSession.addInput(videoInput)
        captureSession.addOutput(metadataOutput)

        metadataOutput.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
        metadataOutput.metadataObjectTypes = [.qr]
        
        previewLayer.videoGravity = .resizeAspectFill
        self.captureSession = captureSession
        
        
        frameView.layer.borderWidth = 1
        frameView.layer.cornerRadius = 8
        frameView.layer.borderColor = UIColor.white.cgColor
        
        cameraView.layer.insertSublayer(previewLayer, at: 0)
        self.previewLayer = previewLayer
    }
    
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer.frame = cameraView.bounds
    }
    
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        if captureSession != nil {
            startScan()
        }
        else {
            delegate?.qrCodeViewDidFail()
        }
    }
    
    @IBAction func cancelAction(_ sender: AnyObject) {
        delegate?.qrCodeViewDidCancel()
    }
    
    private func startScan() {
        if captureSession?.isRunning == false {
            DispatchQueue.global(qos: .background).async {
                self.captureSession?.startRunning()
            }
        }
    }

    private func stopScan() {
        if captureSession?.isRunning == true {
            captureSession?.stopRunning()
        }
    }
}

extension QRCodeReaderViewController: AVCaptureMetadataOutputObjectsDelegate {
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        stopScan()
        guard
            let metadataObject = metadataObjects.first,
            let readableObject = metadataObject as? AVMetadataMachineReadableCodeObject,
            let stringValue = readableObject.stringValue
        else { return }
        AudioServicesPlaySystemSound(SystemSoundID(kSystemSoundID_Vibrate))
        delegate?.qrCodeViewDidScan(qrCodeValue: stringValue)
    }
}
