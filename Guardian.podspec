# .version is the single source of the release version (set by Prepare release).
version = File.read(File.join(__dir__, '.version')).strip
Pod::Spec.new do |s|
  s.name             = 'Guardian'
  s.version          = version
  s.summary          = "Swift toolkit for Auth0 Guardian API"
  s.description      = <<-DESC
                        Auth0 Guardian API toolkit written in Swift for iOS apps
                        DESC
  s.homepage         = 'https://github.com/auth0/Guardian.swift'
  s.license          = 'MIT'
  s.author           = { 'Auth0' => 'support@auth0.com' }
  s.source           = { :git => 'https://github.com/auth0/Guardian.swift.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/auth0'

  s.ios.deployment_target = '15.0'
  s.requires_arc = true
  s.swift_versions = ['5.0']

  s.ios.source_files = 'Guardian/**/*.{swift,h,m}'
  # Ships the privacy manifest to CocoaPods apps in a Guardian.bundle (SPM: resources in Package.swift).
  s.resource_bundles = { s.name => 'Guardian/PrivacyInfo.xcprivacy' }
  s.ios.frameworks = 'UIKit'
end
