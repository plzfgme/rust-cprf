pub mod ggm;

use pyo3::prelude::*;

#[pymodule]
fn pycprf(py: Python, m: &PyModule) -> PyResult<()> {
    ggm::register(py, m)?;
    Ok(())
}
