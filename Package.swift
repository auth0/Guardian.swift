// swift-tools-version:5.10
import PackageDescription


let package = Package(
    name: "Guardian",
    platforms: [
        .iOS(.v12)
    ],
    products: [
        .library(
            name: "Guardian",
            targets: ["Guardian"])
    ],
    dependencies: [
        .package(url: "https://github.com/Quick/Quick.git", .upToNextMajor(from: "7.0.0")),
        .package(url: "https://github.com/Quick/Nimble.git", .upToNextMajor(from: "12.0.0")),
    ],
    targets: [
        .target(
            name: "Guardian",
            dependencies: [],
            path: "Guardian",
            exclude: ["Info.plist"]
        ),
        .testTarget(
            name: "GuardianTests",
            dependencies: [
                "Guardian",
                .product(name: "Quick", package: "Quick"),
                .product(name: "Nimble", package: "Nimble"),
            ],
            path: "GuardianTests",
            exclude: ["Info.plist"]
        )
    ]
)