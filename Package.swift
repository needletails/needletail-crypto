// swift-tools-version:6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "needletail-crypto",
    platforms: [
        .macOS(.v15),
        .iOS(.v18)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "NeedleTailCrypto",
            targets: ["NeedleTailCrypto"]),
    ],
    dependencies: [
        .package(url: "https://github.com/needletails/swift-crypto.git",  from: "1.0.1"), traits: ["FORCE_BUILD_SWIFT_CRYPTO_API"]),
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.1.3")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "NeedleTailCrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Collections", package: "swift-collections")
            ],
        ),
        .testTarget(
            name: "NeedleTailCryptoTests",
            dependencies: [
                "NeedleTailCrypto"
            ]),
    ]
)
