pub type TestResult = Result<(), TestError>;


pub type TestError = Box<dyn std::error::Error>;


pub type Failure = (fn() -> cloud_posture::error::StoreError, axum::http::StatusCode, &'static str);
