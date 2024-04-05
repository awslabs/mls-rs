// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "cryptokit-bridge",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "cryptokit-bridge", type: .static, targets: ["cryptokit-bridge"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "cryptokit-bridge", dependencies: []),
    ]
)
