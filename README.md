# Guardian SDK for iOS
============
[![CI Status](https://travis-ci.com/auth0/Guardian.swift.svg?token=R3xUbi1dnaoneyhnspcr&branch=master)](https://travis-ci.com/auth0/Guardian.swift)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat)](http://doge.mit-license.org)

[Guardian](https://auth0.com/docs/multifactor-authentication/guardian) is Auth0's multi-factor
authentication (MFA) service that provides a simple, safe way for you to implement MFA.

[Auth0](https://auth0.com) is an authentication broker that supports social identity providers as
well as enterprise identity providers such as Active Directory, LDAP, Google Apps and Salesforce.

This SDK allows you to integrate Auth0's Guardian multi-factor service in your own app, transforming
it in the second factor itself. Your users will get all the benefits of our frictionless
multi-factor authentication from your app.

## Requirements

iOS 9.3+ and Swift 3 is required in order to use Guardian.

## Before getting started

To use this SDK you have to configure your tenant's Guardian service with your own push notification
credentials, otherwise you would not receive any push notifications. Please read the
[docs](https://auth0.com/docs/multifactor-authentication/guardian) about how to accomplish that.

##Install

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

## Usage

`Guardian` is the core of the SDK. To get things going you'll have to import the library:

```swift
import Guardian
```

Then you'll need the domain for your specific tenant/url:

```swift
let domain = "tenant.guardian.auth0.com"
```

### Enroll

An enrollment is a link between the second factor and an Auth0 account. When an account is enrolled
you'll need the enrollment data to provide the second factor required to verify the identity.

You can create an enrolment using the `Guardian.enroll` function.

First you'll need to obtain the enrollment info by scanning a Guardian QR code or obtaining an
enrollment ticket by email for example.

Next you'll have to create a new pair of RSA keys for the new enrollment. The private key will be
used to sign the requests to allow or reject a login. The public key will be sent during the enroll
process so the server can later verify the request's signature.
The keys will be stored on the keychain, and we'll later access them by `tag`, so you should
use a unique identifier every time you create them.

```swift
let rsaKeyPair = RSAKeyPair.new(usingPublicTag: "com.auth0.guardian.enroll.public",
                                privateTag: "com.auth0.guardian.enroll.private")
```

You can then use the `Guardian.enroll` function, like this:

```swift
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

You must provide the `notificationToken`. It is the token required to send push notification to the device using the Apple Push Notification service (APNs). In case your app is not yet using push notifications or you're not familiar with it, you should check their
[docs](https://developer.apple.com/go/?id=push-notifications).

The notification token MUST be a String containing the 64 bytes (expressed in hexadecimal format) as received on `application(:didRegisterForRemoteNotificationsWithDeviceToken)`

### Unenroll

If you want to delete an enrollment -for example if you want to disable MFA- you can make the
following request:

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

### Allow a login request

Once you have the enrollment in place, you will receive a push notification every time the user
has to validate his identity with MFA.

Guardian provides a method to parse the data received from APNs and return a `Notification`
instance ready to be used.

For example, in your `AppDelegate` you might have something like this:

```swift
func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any]) {
    // when the app is open and we receive a push notification

    if let notification = Guardian.notification(from: userInfo) {
        // we have received a Guardian push notification
    }
}
```

Once you have the notification instance, you can easily allow the authentication request by using
the `allow` method. You'll also need the enrollment that you obtained previously.
In case you have more than one enrollment, you'll have to find the one that has the same `id` as the
notification (the `enrollmentId` property).

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

### Reject a login request

To deny an authentication request just call `reject` instead. You can also send a reject reason if
you want. The reject reason will be available in the guardian logs.

```swift
Guardian
        .authentication(forDomain: domain, andEnrollment: enrollment)
        .reject(notification: notification)
        // or reject(notification: notification, withReason: "hacked")
        .start { result in
            switch result {
            case .success: 
                // the auth request was successfuly rejected
            case .failure(let cause):
                // something failed, check cause to see what went wrong
            }
        }
```

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders),
either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce,
amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory,
ADFS or any SAML Identity Provider**.
* Add authentication through more traditional
**[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with
the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and
**flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through
[JavaScript rules](https://docs.auth0.com/rules).

## Create a free account in Auth0

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository
issues section. Please do not report security vulnerabilities on the public GitHub issue tracker.
The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for
disclosing security issues.

## Author

[Auth0](https://auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
