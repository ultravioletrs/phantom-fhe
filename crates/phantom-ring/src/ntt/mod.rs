//! Negacyclic NTT backend abstraction.

pub mod backend;
pub mod cpu;
pub mod table;

pub use backend::NttBackend;
pub use cpu::CpuNttBackend;
pub use table::NttTable;
