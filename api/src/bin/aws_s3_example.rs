use anyhow::Context;
use anyhow::Result;
use fira_api::storage::build_client;


#[tokio::main]
async fn main() -> Result<()> {
    println!("=== AWS S3 Example ===\n");

    let s3_client = build_client("FIRA").context("Failed to build local S3 client")?;
    let bucket_name = "fira-test-attachments";

    // Create bucket
    s3_client.create_bucket().bucket(bucket_name)
        .send().await.with_context(|| format!("Failed to create bucket {bucket_name}"))?;

    // List buckets
    let res = s3_client.list_buckets()
        .send().await.context("Failed to list buckets")?;

    println!("Total buckets number is {:?}", res.buckets().len());
    for bucket in res.buckets() {
        println!("Bucket: {:?}", bucket.name());
    }

    // hello world file upload
    let data = "hello, world!".as_bytes().to_vec();
    let key = "test_file.txt";
    let body = aws_sdk_s3::primitives::ByteStream::from(data);
    s3_client.put_object()
        .bucket(bucket_name)
        .key(key)
        .body(body)
        .send().await.with_context(|| format!("upload to bucket {bucket_name} with key {key}"))?;

    
    // List objects in the bucket
    let list_objects_res = s3_client.list_objects_v2()
        .bucket(bucket_name)
        .send().await.with_context(|| format!("list objects in bucket {bucket_name}"))?;
    for object in list_objects_res.contents() {
        println!("Object: {:?}", object.key());
    }

    // Download the file
    let get_object_res = s3_client.get_object()
        .bucket(bucket_name)
        .key(key)
        .send().await.with_context(|| format!("download {bucket_name} with key {key}"))?;
    let downloaded_data = get_object_res.body.collect().await
        .with_context(|| format!("read data from bucket {bucket_name} with key {key}"))?;
    let downloaded_string = String::from_utf8(downloaded_data.into_bytes().to_vec())
        .with_context(|| format!("bytes to string, key: {key}"))?;
    println!("Downloaded file content: {}", downloaded_string);

    println!("\n=== Done ===");
    Ok(())
}
