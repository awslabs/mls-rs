// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("./proto/mls_client.proto")?;
    Ok(())
}
