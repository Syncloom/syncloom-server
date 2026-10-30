use crate::config::BlobBackend;
use crate::error::ApiResult;
use bytes::Bytes;
use object_store::{aws::AmazonS3Builder, local::LocalFileSystem, path::Path, ObjectStore, PutPayload};
use std::sync::Arc;

#[derive(Clone)]
pub struct Blobs {
    store: Arc<dyn ObjectStore>,
}

fn path(hash: &str) -> Path {
    Path::from(format!("chunks/{}/{}", &hash[..2], hash))
}

impl Blobs {
    pub fn new(cfg: &BlobBackend) -> Result<Blobs, String> {
        let store: Arc<dyn ObjectStore> = match cfg {
            BlobBackend::Fs(dir) => {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                Arc::new(LocalFileSystem::new_with_prefix(dir).map_err(|e| e.to_string())?)
            }
            BlobBackend::S3 { bucket, region, endpoint, access_key, secret_key } => {
                let mut b = AmazonS3Builder::new().with_bucket_name(bucket).with_region(region);
                if let Some(e) = endpoint {
                    b = b.with_endpoint(e).with_allow_http(true).with_virtual_hosted_style_request(false);
                }
                if let (Some(a), Some(s)) = (access_key, secret_key) {
                    b = b.with_access_key_id(a).with_secret_access_key(s);
                }
                Arc::new(b.build().map_err(|e| e.to_string())?)
            }
        };
        Ok(Blobs { store })
    }

    pub async fn put(&self, hash: &str, data: Bytes) -> ApiResult<()> {
        self.store.put(&path(hash), PutPayload::from_bytes(data)).await?;
        Ok(())
    }
    pub async fn get(&self, hash: &str) -> ApiResult<Bytes> {
        Ok(self.store.get(&path(hash)).await?.bytes().await?)
    }
    pub async fn delete(&self, hash: &str) -> ApiResult<()> {
        match self.store.delete(&path(hash)).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
