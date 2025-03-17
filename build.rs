use std::error::Error;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    // Find all proto files in the proto directory tree
    let proto_files = glob::glob("proto/**/*.proto")?
        .collect::<Result<Vec<_>, _>>()?;
    
    if proto_files.is_empty() {
        return Err("No .proto files found in the proto directory".into());
    }
    
    // Print which files will be recompiled if changed
    for proto_file in &proto_files {
        println!("cargo:rerun-if-changed={}", proto_file.display());
    }
    
    // Ensure we include the root proto directory as an include path
    // This is crucial for resolving imports across the nested structure
    let proto_include_dir = Path::new("proto");
    
    // Create a configured builder
    let config = tonic_build::configure()
        .build_server(true)
        .build_client(true);
        
    // Convert paths to strings for tonic_build
    let proto_paths: Vec<String> = proto_files
        .iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect();
    
    // Compile all proto files at once with the proper include path
    config.compile_protos(&proto_paths, &[proto_include_dir])?;
    
    Ok(())
}