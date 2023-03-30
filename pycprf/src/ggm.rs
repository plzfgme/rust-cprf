use pyo3::{exceptions::PyException, prelude::*, types::PyBytes};

#[pyclass]
struct Ggm64MasterKey {
    key: cprf::ggm::Ggm64MasterKey,
}

#[pymethods]
impl Ggm64MasterKey {
    #[new]
    fn new(key: &[u8]) -> Ggm64MasterKey {
        Ggm64MasterKey {
            key: cprf::ggm::Ggm64MasterKey::new_from_slice(key),
        }
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.key).map_err(|e| PyException::new_err(e.to_string()))
    }

    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Ggm64MasterKey> {
        match serde_json::from_str(json) {
            Ok(k) => Ok(Ggm64MasterKey { key: k }),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    fn evaluate(&self, py: Python<'_>, input: u64) -> Py<PyBytes> {
        PyBytes::new(py, &self.key.evaluate(input)).into()
    }

    fn constrain(&self, a: u64, b: u64) -> Ggm64ConstrainedKey {
        Ggm64ConstrainedKey {
            key: self.key.constrain(a, b),
        }
    }
}

#[pyclass]
struct Ggm64ConstrainedKey {
    key: cprf::ggm::Ggm64ConstrainedKey,
}

#[pymethods]
impl Ggm64ConstrainedKey {
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.key).map_err(|e| PyException::new_err(e.to_string()))
    }

    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Ggm64ConstrainedKey> {
        match serde_json::from_str(json) {
            Ok(k) => Ok(Ggm64ConstrainedKey { key: k }),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    fn evaluate(&self, py: Python<'_>, input: u64) -> Option<Py<PyBytes>> {
        self.key
            .evaluate(input)
            .map(|r| PyBytes::new(py, &r).into())
    }
}

pub fn register(py: Python, parent_module: &PyModule) -> PyResult<()> {
    let child_module = PyModule::new(py, "ggm")?;
    child_module.add_class::<Ggm64MasterKey>()?;
    child_module.add_class::<Ggm64ConstrainedKey>()?;
    parent_module.add_submodule(child_module)?;
    Ok(())
}
