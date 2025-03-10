// DynamicAuthorizationDetailsView.swift
//
// Copyright (c) 2025 Auth0 (http://auth0.com)
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

class DynamicAuthorizationDetailsView: UIStackView {
    init(fromAuthorizationDetails authorizationDetails: [Json]) {
        super.init(frame: .zero)
        self.axis = .vertical
        self.distribution = .fillProportionally
        
        for authDetail in authorizationDetails {
            let headerLabel = UILabel()
            headerLabel.text = authDetail["type"]?.stringValue?.replacingOccurrences(of: "_", with: " ").uppercased()
            headerLabel.font = UIFont.preferredFont(forTextStyle: .footnote)
            headerLabel.heightAnchor.constraint(greaterThanOrEqualToConstant: 30).isActive = true
            
            self.addArrangedSubview(headerLabel)
            for (key, value) in authDetail.objectValue!.filter({$0.key != "type"}) {
                // For simplicity we wont search nested objects in this example
                if value.objectValue != nil || value.arrayValue != nil {
                    continue
                }
                
                let stack = UIStackView();
                stack.axis = .horizontal
                stack.distribution = .equalSpacing
                
                let keyLabel = UILabel()
                keyLabel.text = key.replacingOccurrences(of: "_", with: " ").uppercased()
                keyLabel.font = UIFont.preferredFont(forTextStyle: .footnote)
                
                let valueLabel = UILabel()
                valueLabel.text = value.stringValue ?? value.doubleValue?.description ?? value.boolValue?.description
                valueLabel.font = UIFont.preferredFont(forTextStyle: .headline)
                
                stack.addArrangedSubview(keyLabel)
                stack.addArrangedSubview(valueLabel)
                self.addArrangedSubview(stack)
            }
        }
        
    }
    
    required init(coder aDecoder: NSCoder) {
        super.init(coder: aDecoder)
    }
}
