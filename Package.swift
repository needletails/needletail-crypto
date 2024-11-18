// swift-tools-version:6.0
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
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.7.1")),
        .package(url: "https://github.com/apple/swift-collections.git", .upToNextMajor(from: "1.1.3")),
        .package(url: "https://github.com/apple/swift-testing.git", .upToNextMajor(from: "0.10.0")),
        .package(url: "git@github.com:needle-tail/needletail-helpers.git", .upToNextMajor(from: "1.0.4")),
        .package(url: "https://github.com/needle-tail/needletail-algorithms.git", .upToNextMajor(from: "1.0.10")),
        .package(url: "https://github.com/orlandos-nl/BSON.git", from: "8.1.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "NeedleTailCrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Collections", package: "swift-collections"),
                .product(name: "NeedleTailHelpers", package: "needletail-helpers"),
                .product(name: "NeedleTailAlgorithms", package: "needletail-algorithms"),
                .product(name: "BSON", package: "BSON")
            ]
        ),
        .testTarget(
            name: "NeedleTailCryptoTests",
            dependencies: [
                "NeedleTailCrypto",
                .product(name: "Testing", package: "swift-testing")
            ]),
    ]
)
