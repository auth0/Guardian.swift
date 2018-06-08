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

### ios release_prepare
```
fastlane ios release_prepare
```
Prepares the library for release by updating versions and creating release pull request

You need to specify the type of release with the `bump` parameter with the values [major|minor|patch]
### ios release_perform
```
fastlane ios release_perform
```
Performs the prepared release by creating a tag and pusing to remote
### ios release_publish
```
fastlane ios release_publish
```
Releases the library to CocoaPods trunk & Github Releases

----

This README.md is auto-generated and will be re-generated every time [fastlane](https://fastlane.tools) is run.
More information about fastlane can be found on [fastlane.tools](https://fastlane.tools).
The documentation of fastlane can be found on [docs.fastlane.tools](https://docs.fastlane.tools).
