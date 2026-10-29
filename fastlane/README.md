fastlane documentation
----

# Installation

Make sure you have the latest version of the Xcode command line tools installed:

```sh
xcode-select --install
```

For _fastlane_ installation instructions, see [Installing _fastlane_](https://docs.fastlane.tools/#installing-fastlane)

# Available Actions

## iOS

### ios bootstrap

```sh
[bundle exec] fastlane ios bootstrap
```



### ios test

```sh
[bundle exec] fastlane ios test
```



### ios coverage

```sh
[bundle exec] fastlane ios coverage
```

Runs tests and generates a Slather coverage report (cobertura XML) for upload to Codecov

### ios lint

```sh
[bundle exec] fastlane ios lint
```

Runs SwiftLint. Fails the lane only on error-severity violations (no --strict).

Also emits a checkstyle XML to output/ for the reports dashboard.

### ios build

```sh
[bundle exec] fastlane ios build
```

Assembles the Guardian framework (informational; mirrors Android's build lane)

### ios ci

```sh
[bundle exec] fastlane ios ci
```



### ios apns

```sh
[bundle exec] fastlane ios apns
```



### ios publish_cocoapods

```sh
[bundle exec] fastlane ios publish_cocoapods
```

Pushes Guardian.podspec to CocoaPods trunk (the podspec source is the X.Y.Z tag).

Requires RELEASE_CONTEXT=true, only set inside the publish job of release.yml,

and COCOAPODS_TRUNK_TOKEN from the cocoapods-release environment.

----

This README.md is auto-generated and will be re-generated every time [_fastlane_](https://fastlane.tools) is run.

More information about _fastlane_ can be found on [fastlane.tools](https://fastlane.tools).

The documentation of _fastlane_ can be found on [docs.fastlane.tools](https://docs.fastlane.tools).
