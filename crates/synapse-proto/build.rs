fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build with a bundled `protoc` unless one is provided, so `cargo build` needs no system
    // protobuf compiler (CI runners, contributors' machines and containers rarely have one).
    if std::env::var_os("PROTOC").is_none() {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_build::compile_protos("proto/synapse.proto")?;
    Ok(())
}
