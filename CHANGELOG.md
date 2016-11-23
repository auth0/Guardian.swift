## [0.1.0](https://github.com/auth0/Guardian.swift/tree/0.1.0) (2016-11-23)

First release of Guardian for iOS

### Requirements

iOS 9.3+ and Swift 3 is required in order to use Guardian.

### Install

#### CocoaPods

Guardian.swift is available through [CocoaPods](http://cocoapods.org). 
To install it, simply add the following line to your Podfile:

```ruby
pod "Guardian", '~> 0.1.0'
```

#### Carthage

In your Cartfile add this line

```
github "auth0/Guardian.swift" ~> 0.1.0
```

### Usage

To get things going you'll have to import the library:

```swift
import Guardian
```

Then you'll need the domain for your specific tenant/url:

```swift
let domain = "<TENANT>.guardian.auth0.com"
```

To create an enroll, create a pair of RSA keys, obtain the Guardian enrollment data from a Guardian QR code and use it like this:

```swift
let rsaKeyPair = RSAKeyPair.new(usingPublicTag: "com.auth0.guardian.enroll.public",
                                privateTag: "com.auth0.guardian.enroll.private")

let enrollmentUriFromQr: String = ... // the URI obtained from a Guardian QR code
let apnsToken: String = ... // the APNS token of this device, where notifications will be sent

Guardian
        .enroll(forDomain: domain,
                usingUri: enrollmentUriFromQr,
                notificationToken: apnsToken,
                keyPair: rsaKeyPair)
        .start { result in
            switch result {
            case .success(let enrollment): 
                // success, we have the enrollment data available
            case .failure(let cause):
                // something failed, check cause to see what went wrong
            }
        }
```

To unenroll just call:

```swift
Guardian
        .api(forDomain: domain)
        .device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
        .delete()
        .start { result in
            switch result {
            case .success: 
                // success, the enrollment was deleted
            case .failure(let cause):
                // something failed, check cause to see what went wrong
            }
        }
```

To allow or reject a login request you first need to get the Guardian `Notification`. In your `AppDelegate` add something like this:

```swift
func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any]) {
    // when the app is open and we receive a push notification

    if let notification = Guardian.notification(from: userInfo) {
        // we have received a Guardian push notification
    }
}
```

Then, to allow the login request, call:

```swift
Guardian
        .authentication(forDomain: domain, andEnrollment: enrollment)
        .allow(notification: notification)
        .start { result in
            switch result {
            case .success: 
                // the auth request was successfuly allowed
            case .failure(let cause):
                // something failed, check cause to see what went wrong
            }
        }
```

or to reject it (optionally you can also indicate a reject reason):

```swift
Guardian
        .authentication(forDomain: domain, andEnrollment: enrollment)
        .reject(notification: notification)
        // or .reject(notification: notification, withReason: "hacked")
        .start { result in
            switch result {
            case .success: 
                // the auth request was successfuly rejected
            case .failure(let cause):
                // something failed, check cause to see what went wrong
            }
        }
```
