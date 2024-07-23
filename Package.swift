// swift-tools-version:5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "needletail-crypto",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "NeedleTailCrypto",
            targets: ["NeedleTailCrypto"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "2.6.0"..."3.3.0"),
        .package(url: "git@github.com:needle-tail/swift-data-to-file.git", .upToNextMajor(from: "1.0.2")),
        .package(url: "https://github.com/orlandos-nl/BSON.git", from: "8.1.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "NeedleTailCrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SwiftDTF", package: "swift-data-to-file"),
                .product(name: "BSON", package: "BSON")
            ]
        ),
        .testTarget(
            name: "NeedleTailCryptoTests",
            dependencies: ["NeedleTailCrypto"]),
    ]
)
