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



### ios release_prepare

```sh
[bundle exec] fastlane ios release_prepare
```

Prepares the library for release by updating versions and creating release pull request

You need to specify the type of release with the `bump` parameter with the values [major|minor|patch]

### ios release_perform

```sh
[bundle exec] fastlane ios release_perform
```

Performs the prepared release by creating a tag and pusing to remote

### ios release_publish

```sh
[bundle exec] fastlane ios release_publish
```

Releases the library to CocoaPods trunk & Github Releases

----

This README.md is auto-generated and will be re-generated every time [_fastlane_](https://fastlane.tools) is run.

More information about _fastlane_ can be found on [fastlane.tools](https://fastlane.tools).

The documentation of _fastlane_ can be found on [docs.fastlane.tools](https://docs.fastlane.tools).
