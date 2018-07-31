version = `agvtool mvers -terse1`.strip
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

  s.ios.deployment_target = '10.0'
  s.requires_arc = true
  s.swift_version = '4.1'

  s.ios.source_files = 'Guardian/**/*.{swift,h,m}'
  s.ios.frameworks = 'UIKit'
end
