// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "cryptokit-bridge",
    platforms: [
        .macOS(.v14),
        .iOS(.v16),
    ],
    products: [
        .library(name: "cryptokit-bridge", type: .static, targets: ["cryptokit-bridge"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "cryptokit-bridge", dependencies: []),
        .testTarget(name: "cryptokit-bridge-tests", dependencies: ["cryptokit-bridge"])        
    ]
)
