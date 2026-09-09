use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct RawEvent {
    pub timestamp: u64,
    pub tid: i64,
    pub type_id: u16,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait EventSource: Send {
    async fn next_event(&mut self) -> Option<RawEvent>;
}

pub struct NodriverSource;

#[async_trait]
impl EventSource for NodriverSource {
    async fn next_event(&mut self) -> Option<RawEvent> {
        None
    }
}
