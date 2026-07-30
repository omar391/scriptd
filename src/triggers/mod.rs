mod evaluator;
mod schema;
mod sensors;

pub use evaluator::{
    SensorSnapshot, TriggerDispatch, TriggerPhase, TriggerRuntime, TriggerState, WifiSnapshot,
};
pub use schema::{Condition, FirePolicy, TriggerConfig, TriggerMap};
pub use sensors::{SensorSuite, WifiEventWatcher};

#[cfg(test)]
pub use evaluator::Truth;
#[cfg(test)]
mod tests;
