fastlane documentation
================
# Installation

Make sure you have the latest version of the Xcode command line tools installed:

```
xcode-select --install
```

Install _fastlane_ using
```
[sudo] gem install fastlane -NV
```
or alternatively using `brew cask install fastlane`

# Available Actions
## iOS
### ios bootstrap
```
fastlane ios bootstrap
```

### ios test
```
fastlane ios test
```

### ios ci
```
fastlane ios ci
```

### ios apns
```
fastlane ios apns
```

### ios library_release
```
fastlane ios library_release
```
Releases the library to Cocoapods & Github Releases and updates README/CHANGELOG

You need to specify the type of release with the `bump` parameter with the values [major|minor|patch]

----

This README.md is auto-generated and will be re-generated every time [fastlane](https://fastlane.tools) is run.
More information about fastlane can be found on [fastlane.tools](https://fastlane.tools).
The documentation of fastlane can be found on [docs.fastlane.tools](https://docs.fastlane.tools).
