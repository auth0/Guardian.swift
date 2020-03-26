# Guardian.swift (iOS) - Sample Application


[Guardian](https://auth0.com/docs/multifactor-authentication/guardian) is Auth0's multi-factor
authentication (MFA) service that provides a simple, safe way for you to implement MFA.

[Auth0](https://auth0.com) is an authentication broker that supports social identity providers as
well as enterprise identity providers such as Active Directory, LDAP, Google Apps and Salesforce.

This is the sample app that demonstrates how to integrate the Auth0's Guardian SDK into your own app

## Requirements

iOS 10+ and Swift 4.1 is required in order to use Guardian.

## Before getting started

To use this SDK you have to configure your tenant's Guardian service with your own push notification
credentials, otherwise you would not receive any push notifications. Please read the
[docs](https://auth0.com/docs/multifactor-authentication/guardian) about how to accomplish that.

## Install

#### Carthage

Install the Carthage dependencies from the root of the repo

```bash
carthage bootstrap --platform iOS --no-use-binaries --cache-builds
```
This step must complete successfully before the Xcode project will be able to be built.

#### Xcode

To configure the sample app open the Guardian Ccode project file in the root of the repo and navigate to the "AppDelegate.swift" file.  Edit the following line to use your tenant name before the `.guardian.auth0.com`.  In other words, replace the text `guardian-demo` with the name of your Auth0 tenant.

```swift
static let guardianDomain = "guardian-demo.guardian.auth0.com"
```
Which should be similar to the following:

```swift
let domain = "{YOUR_ACCOUNT_NAME}.guardian.auth0.com"
```

You may need to adjust the bundle identifier for the sample `GuardianApp` target to reflect the identifier you used when setting up your Apple Push Notification in the Apple Developer dashboard.

You may also need to update the Xcode project's Code Signing Identity settings (found in the Build Settings) to reflect your Xcode Developer configuration.

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
