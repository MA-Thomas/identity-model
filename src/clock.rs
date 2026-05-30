use crate::fen::Timestamp;

pub trait Clock {
    fn now(&self) -> Timestamp;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedClock {
    pub timestamp: Timestamp,
}

impl FixedClock {
    pub fn new(timestamp: Timestamp) -> Self {
        Self { timestamp }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.timestamp.clone()
    }
}
