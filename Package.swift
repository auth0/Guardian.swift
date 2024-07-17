// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "Guardian",
    platforms: [
        .iOS(.v12)
    ],
    products: [
        .library(
            name: "Guardian",
            targets: [
                "Guardian"
            ]
        )
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "GuardianObjC",
            path: "Guardian/Crypto",
            sources: [
                "A0HMAC.m",
                "A0RSA.m",
                "A0SHA.m"
            ],
            publicHeadersPath: "."
        ),
        .target(
            name: "Guardian",
            dependencies: [
                "GuardianObjC"
            ],
            path: "Guardian",
            exclude: ["Info.plist"],
            sources: [
                "API",
                "Authentication",
                "Crypto/Base32.swift",
                "Crypto/Data+Base64URL.swift",
                "Crypto/JWT.swift",
                "Guardian.swift",
                "Enrollment",
                "Generators",
                "Keys",
                "Networking"
            ],
            resources: [
                .process("PrivacyInfo.xcprivacy")
            ],
            publicHeadersPath: "Crypto",
            cSettings: [
                .headerSearchPath("Crypto"),
                .define("SWIFT_BRIDGING_HEADER", to: "Guardian/Guardian.h")
            ],
            swiftSettings: [
                .unsafeFlags(["-import-objc-header", "Guardian/Guardian.h"])
            ]
            )
    ]
)
