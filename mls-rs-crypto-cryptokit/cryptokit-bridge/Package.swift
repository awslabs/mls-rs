// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "cryptokit-bridge",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "cryptokit-bridge",
            type: .static,
            targets: ["cryptokit-bridge"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "cryptokit-bridge", dependencies: []),
        .testTarget(name: "cryptokit-bridge-tests", dependencies: ["cryptokit-bridge"])
    ]
)
