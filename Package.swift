// swift-tools-version:6.4
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
        .package(url: "https://github.com/apple/swift-crypto.git",  from: "5.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "NeedleTailCrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
        ),
        .testTarget(
            name: "NeedleTailCryptoTests",
            dependencies: [
                "NeedleTailCrypto"
            ]),
    ]
)
