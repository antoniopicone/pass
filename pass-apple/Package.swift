// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PassKit",
    platforms: [
        // iOS 17 / macOS 14: the app views use ContentUnavailableView and
        // the two-parameter onChange(of:) signature, both introduced then.
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "PassKit", targets: ["PassKit"]),
    ],
    targets: [
        // The compiled passlib_ffi Rust static library, as a multi-platform
        // XCFramework (macOS + iOS device + iOS Simulator slices), with the
        // passlib_ffi.h header attached so PassKit can `import PassKitFFI`.
        //
        // This directory does not exist until you run
        // `build-xcframework.sh` on a Mac — see the top-level README in
        // this directory. Until then, resolving this package fails with a
        // clear "missing binary target" error, which is expected.
        .binaryTarget(
            name: "PassKitFFI",
            path: "PassKitFFI.xcframework"
        ),
        .target(
            name: "PassKit",
            dependencies: ["PassKitFFI"],
            path: "Sources/PassKit"
        ),
    ]
)
