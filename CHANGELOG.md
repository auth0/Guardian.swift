# Change Log

## [0.4.0](https://github.com/auth0/Guardian.swift/tree/0.4.0) (2018-06-08)
[Full Changelog](https://github.com/auth0/Guardian.swift/compare/0.3.1...0.4.0)

**Added**
- Add fastlane release plugin [\#59](https://github.com/auth0/Guardian.swift/pull/59) ([hzalaz](https://github.com/hzalaz))
- Add ability to log requests or add hooks on request/response/error [\#57](https://github.com/auth0/Guardian.swift/pull/57) ([hzalaz](https://github.com/hzalaz))

**Changed**
- Remove warnings from deprecated methods [\#56](https://github.com/auth0/Guardian.swift/pull/56) ([hzalaz](https://github.com/hzalaz))
- Update to Xcode 9.3 [\#55](https://github.com/auth0/Guardian.swift/pull/55) ([hzalaz](https://github.com/hzalaz))

## [0.3.1](https://github.com/auth0/Guardian.swift/tree/0.3.1) (2018-05-25)
[Full Changelog](https://github.com/auth0/Guardian.swift/compare/0.3.0...0.3.1)

**Closed issues**
- Turn off iOS HTTP cache [\#51](https://github.com/auth0/Guardian.swift/issues/51)

**Changed**
- Update project to latests tools and Xcode 9.3 [\#52](https://github.com/auth0/Guardian.swift/pull/52) ([hzalaz](https://github.com/hzalaz))

**Fixed**
- Disable NSURLSession cache [\#53](https://github.com/auth0/Guardian.swift/pull/53) ([hzalaz](https://github.com/hzalaz))

## [0.3.0](https://github.com/auth0/Guardian.swift/tree/0.3.0) (2017-06-02)
[Full Changelog](https://github.com/auth0/Guardian.swift/compare/0.2.0...0.3.0)

**Added**
- Make RSAKeyPair(publicKeyTag:privateKeyTag) constructor public [\#49](https://github.com/auth0/Guardian.swift/pull/49) ([nikolaseu](https://github.com/nikolaseu))
- Add support for appliance [\#48](https://github.com/auth0/Guardian.swift/pull/48) ([nikolaseu](https://github.com/nikolaseu))

## [0.2.0](https://github.com/auth0/Guardian.swift/tree/0.2.0) (2017-01-16)
[Full Changelog](https://github.com/auth0/Guardian.swift/compare/0.1.0...0.2.0)

**Added**
- Make jwk conversion property public [\#47](https://github.com/auth0/Guardian.swift/pull/47) ([hzalaz](https://github.com/hzalaz))
- Add methods to register and handle remote notifications [\#45](https://github.com/auth0/Guardian.swift/pull/45) ([nikolaseu](https://github.com/nikolaseu))

## [0.1.0](https://github.com/auth0/Guardian.swift/tree/0.1.0) (2016-11-23)

First release of Guardian for iOS

## Install

#### CocoaPods

Guardian.swift is available through [CocoaPods](http://cocoapods.org).
To install it, simply add the following line to your Podfile:

```ruby
pod "Guardian"
```

#### Carthage

In your Cartfile add this line

```
github "auth0/Guardian.swift"
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
- Key Pair: A RSA (Private/Public) key pair used to assert your identity with Auth0 Guardian

> In case your app is not yet using push notifications or you're not familiar with it, you should check their [docs](https://developer.apple.com/go/?id=push-notifications).

after your have all of them, you can enroll your device

```swift
Guardian
        .enroll(forDomain: "{YOUR_GUARDIAN_DOMAIN}",
                usingUri: "{ENROLLMENT_URI}",
                notificationToken: "{APNS_TOKEN}",
                keyPair: keyPair)
        .start { result in
            switch result {
            case .success(let enrollment):
                // success, we have the enrollment data available
            case .failure(let cause):
                // something failed, check cause to see what went wrong
            }
        }
```

On success you'll obtain the enrollment information, that should be secured stored in your application. This information includes the enrollment identifier, and the token for Guardian API associated to your device for updating or deleting your enrollment.

#### RSA key pair

Guardian.swift provides a convenience class to generate an RSA key pair and store it in iOS Keychain.

```swift
let rsaKeyPair = RSAKeyPair.new(
    usingPublicTag: "com.auth0.guardian.enroll.public",
    privateTag: "com.auth0.guardian.enroll.private"
    )
```

> The tags should be unique since it's the identifier of each key inside iOS Keychain.

> Since the keys are already secured stored inside iOS Keychain, you olny need to store the identifiers

### Allow a login request

Once you have the enrollment in place, you will receive a push notification every time the user has to validate his identity with MFA.

Guardian provides a method to parse the data received from APNs and return a `Notification` instance ready to be used.

```swift
if let notification = Guardian.notification(from: userInfo) {
    // we have received a Guardian push notification
}
```

Once you have the notification instance, you can easily allow the authentication request by using
the `allow` method. You'll also need the enrollment that you obtained previously.
In case you have more than one enrollment, you'll have to find the one that has the same `id` as the
notification (the `enrollmentId` property).

```swift
Guardian
        .authentication(forDomain: "{YOUR_GUARDIAN_DOMAIN}", andEnrollment: enrollment)
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
