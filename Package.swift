// swift-tools-version:6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "needletail-crypto",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
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
        .package(url: "https://github.com/orlandos-nl/BSON.git", .upToNextMajor(from: "8.1.5")),
        .package(url: "git@github.com:needletails/swift-kyber.git", .upToNextMajor(from: "1.0.1"))
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "NeedleTailCrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Collections", package: "swift-collections"),
                .product(name: "BSON", package: "BSON"),
                .product(name: "SwiftKyber", package: "swift-kyber")
            ]
        ),
        .testTarget(
            name: "NeedleTailCryptoTests",
            dependencies: [
                "NeedleTailCrypto"
            ]),
    ]
)
