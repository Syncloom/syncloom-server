//! gRPC change feed (`Sync.Subscribe`), also served as gRPC-Web for browsers.
use crate::auth::authenticate;
use crate::nodes::fetch_changes;
use crate::state::AppState;
use std::time::Duration;
use syncloom_core::grpc::{sync_server::Sync, Change, SubscribeRequest};
use tokio::sync::{broadcast::error::RecvError, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

pub struct SyncSvc {
    pub state: AppState,
}

const HEARTBEAT: Duration = Duration::from_secs(20);

#[tonic::async_trait]
impl Sync for SyncSvc {
    type SubscribeStream = ReceiverStream<Result<Change, Status>>;

    async fn subscribe(&self, req: Request<SubscribeRequest>) -> Result<Response<Self::SubscribeStream>, Status> {
        let headers = req.metadata().clone().into_headers();
        let state = self.state.clone();
        let user = authenticate(&state, &headers, &["device"]).await.map_err(|_| Status::unauthenticated("invalid token"))?;
        let mut cursor = req.get_ref().since.max(0);
        let (tx, rx) = mpsc::channel(256);
        // subscribe before the first read so nothing slips between the read and the wait
        let mut notify = state.notify.subscribe();
        tokio::spawn(async move {
            loop {
                loop {
                    let batch = match fetch_changes(&state.db, user.id, cursor, 500).await {
                        Ok(b) => b,
                        Err(_) => {
                            let _ = tx.send(Err(Status::internal("database error"))).await;
                            return;
                        }
                    };
                    if batch.is_empty() {
                        break;
                    }
                    for c in batch {
                        cursor = c.cursor;
                        let msg = Change { cursor: c.cursor, node_id: c.node_id, kind: c.kind, version_id: c.version_id.unwrap_or_default(), kv_key: c.kv_key.unwrap_or_default() };
                        if tx.send(Ok(msg)).await.is_err() {
                            return;
                        }
                    }
                }
                let deadline = tokio::time::sleep(HEARTBEAT);
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        r = notify.recv() => match r {
                            Ok(u) if u != user.id => continue,
                            Ok(_) | Err(RecvError::Lagged(_)) => break,
                            Err(RecvError::Closed) => return,
                        },
                        _ = &mut deadline => {
                            // heartbeat + make sure a revoked token ends the stream
                            if authenticate(&state, &headers, &["device"]).await.is_err() {
                                let _ = tx.send(Err(Status::unauthenticated("token revoked"))).await;
                                return;
                            }
                            if tx.send(Ok(Change::default())).await.is_err() {
                                return;
                            }
                            break;
                        }
                        _ = tx.closed() => return,
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
