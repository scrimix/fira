use anyhow::Context;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{Client, config::Credentials};
use std::env;
use anyhow::Result;

#[derive(Clone)]
pub struct S3Config {
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub endpoint_url: String,
}

impl S3Config {
    pub fn from_env(prefix: &str) -> Result<Self> {
        let region = env::var(format!("{prefix}_S3_REGION")).with_context(|| format!("{prefix}_S3_REGION is not set"))?;
        let access_key_id = env::var(format!("{prefix}_S3_ACCESS_KEY_ID")).with_context(|| format!("{prefix}_S3_ACCESS_KEY_ID is not set"))?;
        let secret_access_key = env::var(format!("{prefix}_S3_SECRET_ACCESS_KEY")).with_context(|| format!("{prefix}_S3_SECRET_ACCESS_KEY is not set"))?;
        let endpoint_url = env::var(format!("{prefix}_S3_ENDPOINT_URL")).with_context(|| format!("{prefix}_S3_ENDPOINT_URL is not set"))?;

        Ok(S3Config {
            region,
            access_key_id,
            secret_access_key,
            endpoint_url,
        })
    }
}

pub fn build_client(prefix: &str) -> Result<Client> {
    let config = S3Config::from_env(prefix)
        .with_context(|| format!("Failed to create S3 config for prefix {prefix}"))?;

    let credentials = Credentials::new(
        config.access_key_id,
        config.secret_access_key,
        None,
        None,
        "fira-dev",
    );
    let region = Region::new(config.region);
    let endpoint_url = config.endpoint_url;

    let s3_config = aws_sdk_s3::config::Builder::default()
        .region(region.clone())
        .behavior_version(BehaviorVersion::latest())
        .credentials_provider(credentials.clone())
        .endpoint_url(endpoint_url.clone())
        .force_path_style(true) // important for local S3-compatible services like MinIO or RustFS
        .build();

    let s3_client = Client::from_conf(s3_config);
    Ok(s3_client)
}

#[derive(Clone)]
pub struct LocalStorage {
    pub local_storage_dir: String,
}

impl LocalStorage {
    pub fn new(local_storage_dir: String) -> Self {
        LocalStorage { local_storage_dir }
    }

    pub fn from_env() -> Result<Self> {
        let local_storage_dir = env::var("LOCAL_STORAGE_DIR")
            .with_context(|| "LOCAL_STORAGE_DIR is not set")?;
        Ok(LocalStorage { local_storage_dir })
    }

    pub fn get_full_path(&self, storage_path: &str) -> String {
        format!("{}/{}", self.local_storage_dir, storage_path)
    }

    pub fn write_file(&self, storage_path: &str, data: &[u8]) -> Result<()> {
        let full_path = self.get_full_path(storage_path);
        let parent = std::path::Path::new(&full_path).parent()
            .ok_or_else(|| anyhow::anyhow!("Failed to get parent: {}", storage_path))?;
        std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create parent: {}", storage_path))?;
        std::fs::write(&full_path, data)
            .with_context(|| format!("Failed to write file to {}", full_path))?;
        Ok(())
    }

    pub fn read_file(&self, storage_path: &str) -> Result<Vec<u8>> {
        let full_path = self.get_full_path(storage_path);
        let data = std::fs::read(&full_path)
            .with_context(|| format!("Failed to read file from {}", full_path))?;
        Ok(data)
    }

    pub fn delete_file(&self, storage_path: &str) -> Result<()> {
        let full_path = self.get_full_path(storage_path);
        if std::fs::exists(&full_path)
            .with_context(|| format!("Failed to check existence of file at {}", full_path))?
        {
            std::fs::remove_file(&full_path)
                .with_context(|| format!("Failed to delete file at {}", full_path))?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct S3Storage {
    pub s3_client: Client,
    pub bucket_name: String,
}

impl S3Storage {
    pub fn new(s3_client: Client, bucket_name: String) -> Self {
        S3Storage { s3_client, bucket_name }
    }

    pub fn from_env(prefix: &str) -> Result<Self> {
        let s3_client = build_client(prefix)
            .with_context(|| format!("Failed to build S3 client for prefix {prefix}"))?;
        let bucket_name = env::var(format!("{prefix}_S3_BUCKET_NAME"))
            .with_context(|| format!("{prefix}_S3_BUCKET_NAME is not set"))?;
        Ok(S3Storage { s3_client, bucket_name })
    }

    pub async fn upload_file(&self, key: &str, data: Vec<u8>) -> Result<()> {
        self.s3_client.put_object()
            .bucket(&self.bucket_name)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(data))
            .send()
            .await
            .with_context(|| format!("Failed to upload file to S3 with key {}", key))?;
        Ok(())
    }

    pub async fn download_file(&self, key: &str) -> Result<Vec<u8>> {
        let resp = self.s3_client.get_object()
            .bucket(&self.bucket_name)
            .key(key)
            .send()
            .await
            .with_context(|| format!("Failed to download file from S3 with key {}", key))?;

        let data = resp.body.collect().await
            .with_context(|| format!("Failed to read data from S3 response for key {}", key))?;
        Ok(data.into_bytes().to_vec())
    }

    pub async fn delete_file(&self, key: &str) -> Result<()> {
        self.s3_client.delete_object()
            .bucket(&self.bucket_name)
            .key(key)
            .send()
            .await
            .with_context(|| format!("Failed to delete file from S3 with key {}", key))?;
        Ok(())
    }
}

#[derive(Clone)]
pub enum StorageBackend {
    Local(LocalStorage),
    S3(S3Storage),
}

impl StorageBackend {
    pub fn from_env(prefix: &str) -> Result<Self> {
        let backend_type = env::var(format!("STORAGE_BACKEND"))
            .with_context(|| format!("STORAGE_BACKEND is not set"))?;
        match backend_type.as_str() {
            "local" => {
                let local_storage = LocalStorage::from_env()
                    .with_context(|| "Failed to create LocalStorage from env")?;
                Ok(StorageBackend::Local(local_storage))
            }
            "s3" => {
                let s3_storage = S3Storage::from_env(prefix)
                    .with_context(|| format!("Failed to create S3Storage from env for prefix {prefix}"))?;
                Ok(StorageBackend::S3(s3_storage))
            }
            _ => Err(anyhow::anyhow!("Unknown storage backend type: {}", backend_type)),
        }
    }

    pub async fn write_file(&self, storage_path: &str, data: &[u8]) -> Result<()> {
        match self {
            StorageBackend::Local(local_storage) => local_storage.write_file(storage_path, data),
            StorageBackend::S3(s3_storage) => s3_storage.upload_file(storage_path, data.to_vec()).await,
        }
    }

    pub async fn read_file(&self, storage_path: &str) -> Result<Vec<u8>> {
        match self {
            StorageBackend::Local(local_storage) => local_storage.read_file(storage_path),
            StorageBackend::S3(s3_storage) => s3_storage.download_file(storage_path).await,
        }
    }

    pub async fn delete_file(&self, storage_path: &str) -> Result<()> {
        match self {
            StorageBackend::Local(local_storage) => local_storage.delete_file(storage_path),
            StorageBackend::S3(s3_storage) => s3_storage.delete_file(storage_path).await,
        }
    }
}

pub async fn init_storage_from_env() -> Result<StorageBackend> {
    let backend = StorageBackend::from_env("FIRA")
        .with_context(|| "Failed to initialize storage backend from environment variables")?;
    Ok(backend)
}