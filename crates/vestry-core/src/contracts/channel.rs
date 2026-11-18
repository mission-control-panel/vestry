//! D4 supervisor → single-writer bounded channel. Capacity 64, 5 s submit
//! timeout, 1 MiB transaction cap (PM decision D4).

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use super::primitives::{StateRequestId, UtcMillis};
use super::state::{CommitReceipt, StateError, StateTxn};

pub const STATE_CHANNEL_CAPACITY: usize = 64;
pub const STATE_SUBMIT_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_STATE_TXN_BYTES: usize = 1_048_576;

#[derive(Debug)]
pub struct StateEnvelope {
    pub request_id: StateRequestId,
    pub submitted_at_ms: UtcMillis,
    pub txn: StateTxn,
    pub reply: oneshot::Sender<Result<CommitReceipt, StateError>>,
}

#[derive(Clone)]
pub struct StateWriterHandle {
    tx: mpsc::Sender<StateEnvelope>,
    capacity: usize,
}

impl StateWriterHandle {
    pub fn new(tx: mpsc::Sender<StateEnvelope>) -> Self {
        Self {
            tx,
            capacity: STATE_CHANNEL_CAPACITY,
        }
    }

    /// Bounded FIFO: waits for space, never drops or coalesces. A timeout is
    /// not a commit; the caller must determine whether the request committed.
    pub async fn submit(&self, txn: StateTxn) -> Result<CommitReceipt, StateError> {
        if txn.estimated_bytes() > MAX_STATE_TXN_BYTES {
            return Err(StateError::TransactionTooLarge {
                limit: MAX_STATE_TXN_BYTES,
            });
        }
        let request_id = txn.request_id().clone();
        let submitted_at_ms = txn.submitted_at_ms();
        let (reply, reply_rx) = oneshot::channel();
        let envelope = StateEnvelope {
            request_id,
            submitted_at_ms,
            txn,
            reply,
        };
        match tokio::time::timeout(STATE_SUBMIT_TIMEOUT, self.tx.send(envelope)).await {
            Err(_) => Err(StateError::Backpressure {
                capacity: self.capacity,
            }),
            Ok(Err(_)) => Err(StateError::WriterUnavailable),
            Ok(Ok(())) => match reply_rx.await {
                Ok(result) => result,
                Err(_) => Err(StateError::WriterUnavailable),
            },
        }
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Creates the bounded channel pair used by the composition root.
pub fn state_channel() -> (mpsc::Sender<StateEnvelope>, mpsc::Receiver<StateEnvelope>) {
    mpsc::channel(STATE_CHANNEL_CAPACITY)
}
