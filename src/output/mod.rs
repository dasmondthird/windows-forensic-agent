use anyhow::Result;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

pub struct OutputManager {
    output_dir: PathBuf,
}

impl OutputManager {
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }
    
    pub fn write_json<T: Serialize>(&self, filename: &str, data: &T) -> Result<()> {
        let file_path = self.output_dir.join(filename);
        let json_data = serde_json::to_string_pretty(data)?;
        fs::write(file_path, json_data)?;
        Ok(())
    }
    
    pub fn write_text(&self, filename: &str, content: &str) -> Result<()> {
        let file_path = self.output_dir.join(filename);
        fs::write(file_path, content)?;
        Ok(())
    }
    
    #[cfg(feature = "zip-output")]
    pub fn create_zip(&self) -> Result<()> {
        use std::io::Write;
        use zip::{ZipWriter, write::FileOptions};
        
        let zip_path = self.output_dir.with_extension("zip");
        let zip_file = fs::File::create(&zip_path)?;
        let mut zip = ZipWriter::new(zip_file);
        
        self.add_directory_to_zip(&mut zip, &self.output_dir, "")?;
        
        zip.finish()?;
        log::info!("Created ZIP archive: {}", zip_path.display());
        Ok(())
    }
    
    #[cfg(feature = "zip-output")]
    fn add_directory_to_zip<W: Write + std::io::Seek>(
        &self,
        zip: &mut ZipWriter<W>,
        dir: &Path,
        prefix: &str,
    ) -> Result<()> {
        use zip::write::FileOptions;
        
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o755);
        
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            
            let archive_path = if prefix.is_empty() {
                name_str.to_string()
            } else {
                format!("{}/{}", prefix, name_str)
            };
            
            if path.is_file() {
                zip.start_file(archive_path, options)?;
                let content = fs::read(&path)?;
                zip.write_all(&content)?;
            } else if path.is_dir() {
                zip.add_directory(format!("{}/", archive_path), options)?;
                self.add_directory_to_zip(zip, &path, &archive_path)?;
            }
        }
        
        Ok(())
    }
}
