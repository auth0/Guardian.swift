//
//  QRCodeReaderViewController.swift
//  GuardianApp
//
//  Created by Artem Bakanov on 29/01/2024.
//  Copyright © 2024 Auth0. All rights reserved.
//

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
