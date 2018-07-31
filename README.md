# Guardian.swift (iOS)

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/Guardian.swift.svg?style=flat-square)](https://circleci.com/gh/auth0/Guardian.swift)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/Guardian.swift/master.svg?style=flat-square)](https://codecov.io/github/auth0/Guardian.swift)
[![Version](https://img.shields.io/cocoapods/v/Guardian.svg?style=flat-square)](http://cocoadocs.org/docsets/Guardian)
[![License](https://img.shields.io/cocoapods/l/Guardian.svg?style=flat-square)](http://cocoadocs.org/docsets/Guardian)
[![Platform](https://img.shields.io/cocoapods/p/Guardian.svg?style=flat-square)](http://cocoadocs.org/docsets/Guardian)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat-square)](https://github.com/Carthage/Carthage)
![Swift 4.1](https://img.shields.io/badge/Swift-4.1-orange.svg?style=flat-square)

[Guardian](https://auth0.com/docs/multifactor-authentication/guardian) is Auth0's multi-factor
authentication (MFA) service that provides a simple, safe way for you to implement MFA.

[Auth0](https://auth0.com) is an authentication broker that supports social identity providers as
well as enterprise identity providers such as Active Directory, LDAP, Google Apps and Salesforce.

This SDK allows you to integrate Auth0's Guardian multi-factor service in your own app, transforming
it in the second factor itself. Your users will get all the benefits of our frictionless
multi-factor authentication from your app.

## Requirements

iOS 10+ and Swift 4.1 is required in order to use Guardian.

## Before getting started

To use this SDK you have to configure your tenant's Guardian service with your own push notification
credentials, otherwise you would not receive any push notifications. Please read the
[docs](https://auth0.com/docs/multifactor-authentication/guardian) about how to accomplish that.

## Install

#### CocoaPods

Guardian.swift is available through [CocoaPods](http://cocoapods.org).
To install it, simply add the following line to your Podfile:

```ruby
pod 'Guardian', '~> 1.0.0'
```

#### Carthage

In your Cartfile add this line

```
github "auth0/Guardian.swift" ~> 1.0.0
```

## Usage

`Guardian` is the core of the SDK. To get things going you'll have to import the library:

```swift
import Guardian
```

Then you'll need the Auth0 Guarduan domain for your account:

```swift
let domain = "{YOUR_ACCOUNT_NAME}.guardian.auth0.com"
```

### Enroll

An enrollment is a link between the second factor and an Auth0 account. When an account is enrolled
you'll need it to provide the second factor required to verify the identity.

For an enrollment you need the following things, besides your Guardian Domain:

- Enrollment Uri: The value encoded in the QR Code scanned from Guardian Web Widget or in your enrollment ticket sent to you, e.g. by email.
- APNS Token: Apple APNS token for the device and **MUST** be a `String`containing the 64 bytes (expressed in hexadecimal format)
- Signing & Verification Key: A RSA (Private/Public) key pair used to assert your identity with Auth0 Guardian

> In case your app is not yet using push notifications or you're not familiar with it, you should check their [docs](https://developer.apple.com/go/?id=push-notifications).

after your have all of them, you can enroll your device

```swift
Guardian
        .enroll(forDomain: "{YOUR_GUARDIAN_DOMAIN}",
                usingUri: "{ENROLLMENT_URI}",
                notificationToken: "{APNS_TOKEN}",
                signingKey: signingKey,
                verificationKey: verificationKey
                )
        .start { result in
            switch result {
            case .success(let enrolledDevice):
                // success, we have the enrollment device data available
            case .failure(let cause):
                // something failed, check cause to see what went wrong
            }
        }
```

On success you'll obtain the enrollment information, that should be secured stored in your application. This information includes the enrollment identifier, and the token for Guardian API associated to your device for updating or deleting your enrollment.

#### Signing & Verification Keys

Guardian.swift provides a convenience class to generate a signing key 

```swift
let signingKey = try DataRSAPrivateKey.new()
```

this key only exists in memory but you can obtain its `Data` representation and store securely e.g. in an encrypted SQLiteDB

```swift
// Store data
let data = signingKey.data
// performthe storage

// Load from Storage
let loadedKey = try DataRSAPrivateKey(data: data)
```

But if you just want to store inside iOS Keychain

```swift
let signingKey = try KeychainRSAPrivateKey.new(with: "com.myapp.mytag")
```

It will create it and store it automatically under the supplied tag, if you want to retrieve it using the tag

```swift
let signingKey = try KeychainRSAPrivateKey(tag: "com.myapp.mytag")
```

> The tags should be unique since it's the identifier of each key inside iOS Keychain.

and for the verification key, we can just obtain it from any `SigningKey` like this

```swift
let verificationKey = try signingKey.verificationKey()
```

### Allow a login request

Once you have the enrollment in place, you will receive a push notification every time the user has to validate his identity with MFA.

Guardian provides a method to parse the data received from APNs and return a `Notification` instance ready to be used.

```swift
if let notification = Guardian.notification(from: userInfo) {
    // we have received a Guardian push notification
}
```

Once you have the notification instance, you can easily allow the authentication request by using
the `allow` method. You'll also need some information from the enrolled device that you obtained previously.
In case you have more than one enrollment, you'll have to find the one that has the same `id` as the
notification (the `enrollmentId` property).

When you have the information, `device` parameter is anything that implements the protocol  `AuthenticatedDevice`

```swift
struct Authenticator: Guardian.AuthenticationDevice {
    let signingKey: SigningKey
    let localIdentifier: String
}
```
> Local identifier is the local id of the device, by default on enroll  `UIDevice.current.identifierForVendor`

Then just call

```swift
Guardian
        .authentication(forDomain: "{YOUR_GUARDIAN_DOMAIN}", device: device)
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
        .authentication(forDomain: "{YOUR_GUARDIAN_DOMAIN}", device: device)
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

### Unenroll

If you want to delete an enrollment -for example if you want to disable MFA- you can make the
following request:

```swift
Guardian
        .api(forDomain: "{YOUR_GUARDIAN_DOMAIN}")
        .device(forEnrollmentId: "{USER_ENROLLMENT_ID}", token: "{ENROLLMENT_DEVICE_TOKEN}")
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
