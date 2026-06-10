// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "cryptokit-bridge",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
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
