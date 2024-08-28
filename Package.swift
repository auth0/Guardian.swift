import PackageDescription


let package = Package(
    name: "Guardian",
    platforms: [
        .iOS(.v10)
    ],
    products: [
        .library(
            name: "Guardian",
            targets: ["Guardian"])
    ],
    targets: [
        .target(
            name: "Guardian",
            dependencies: [],
            path: "Guardian"),
        
        .testTarget(
            name: "GuardianTests",
            dependencies: [
                "Guardian",
                .package(url: "https://github.com/Quick/Quick.git", from: "7.3.0"),
                .package(url: "https://github.com/Quick/Nimble.git", from: "12.0.1"),
                .package(url: "https://github.com/auth0/SimpleKeychain", from: "0.12.2")
            ]),
    ]
)
