use fira_api::storage;
use anyhow::{Context, Result};

async fn test_local_storage() -> Result<()> {
    let storage = storage::LocalStorage::from_env()
        .with_context(|| "Failed to create local storage from env")?;

    let test_file_path = "test_storage/test_file.txt";
    let test_data = b"Hello, world!";

    // Write file
    storage.write_file(test_file_path, test_data)
        .with_context(|| format!("Failed to write file: {}", test_file_path))?;
    println!("File written: {}", test_file_path);

    // Read file
    let read_data = storage.read_file(test_file_path)
        .with_context(|| format!("Failed to read file: {}", test_file_path))?;
    println!("File read: {} with content: {:?}", test_file_path, String::from_utf8_lossy(&read_data));

    // Delete file
    storage.delete_file(test_file_path)
        .with_context(|| format!("Failed to delete file: {}", test_file_path))?;
    println!("File deleted: {}", test_file_path);

    Ok(())
}

async fn test_s3_storage() -> Result<()> {
    let storage = storage::S3Storage::from_env("FIRA")
        .with_context(|| "Failed to create S3 storage from env")?;

    let test_file_path = "test_storage/test_file.txt";
    let test_data = b"Hello, S3!".to_vec();

    // Write file
    storage.upload_file(test_file_path, test_data.clone())
        .await.with_context(|| format!("Failed to write file: {}", test_file_path))?;
    println!("File written: {}", test_file_path);

    // Read file
    let read_data = storage.download_file(test_file_path)
        .await.with_context(|| format!("Failed to read file: {}", test_file_path))?;
    println!("File read: {} with content: {:?}", test_file_path, String::from_utf8_lossy(&read_data));

    // Delete file
    storage.delete_file(test_file_path)
        .await.with_context(|| format!("Failed to delete file: {}", test_file_path))?;
    println!("File deleted: {}", test_file_path);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    test_local_storage().await?;
    test_s3_storage().await?;
    Ok(())
}