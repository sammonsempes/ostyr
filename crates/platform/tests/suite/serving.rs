use crate::fixture::{body_json, call, fixture, login, ANALYST, READER};
use crate::types::TestResult;
use axum::body::Body;
use axum::http::StatusCode;


const ROUTES: [(&str, &str); 3] = [("/alerts", "alerts"), ("/cases", "cases"), ("/assets", "cmdb")];


async fn status(router: &axum::Router, method: &str, path: &str, token: Option<&str>) -> Result<StatusCode, crate::types::TestError> {
    Ok(call(router, method, path, token, Body::empty()).await?.status())
}


fn denied(code: StatusCode) -> bool {
    code == StatusCode::UNAUTHORIZED || code == StatusCode::FORBIDDEN
}


#[tokio::test]
async fn one_session_reaches_every_selected_module() -> TestResult {
    let fx = fixture("alerts,cases,cmdb")?;
    let token = login(&fx.router, ANALYST).await?;
    for (path, _module) in ROUTES {
        let code = status(&fx.router, "GET", path, Some(&token)).await?;
        assert!(!denied(code) && code != StatusCode::NOT_FOUND, "{path} {code}");
        assert_eq!(status(&fx.router, "GET", path, None).await?, StatusCode::UNAUTHORIZED, "{path}");
    }
    Ok(())
}


#[tokio::test]
async fn the_permission_survives_the_merge() -> TestResult {
    let fx = fixture("alerts,cases,cmdb")?;
    let token = login(&fx.router, READER).await?;
    for (path, _module) in ROUTES {
        assert_eq!(status(&fx.router, "GET", path, Some(&token)).await?, StatusCode::FORBIDDEN, "{path}");
    }
    Ok(())
}


#[tokio::test]
async fn an_unselected_module_is_denied_by_default() -> TestResult {
    let fx = fixture("alerts")?;
    let token = login(&fx.router, ANALYST).await?;
    assert!(!denied(status(&fx.router, "GET", "/alerts", Some(&token)).await?));
    for path in ["/cases", "/cases/abc", "/assets", "/assets/abc"] {
        assert_eq!(status(&fx.router, "GET", path, Some(&token)).await?, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(status(&fx.router, "GET", path, None).await?, StatusCode::UNAUTHORIZED, "{path}");
    }
    Ok(())
}


#[tokio::test]
async fn other_methods_are_denied_on_every_module_route() -> TestResult {
    let fx = fixture("alerts,cases,cmdb")?;
    let token = login(&fx.router, ANALYST).await?;
    for (path, _module) in ROUTES {
        for method in ["HEAD", "PUT", "POST", "DELETE"] {
            assert!(denied(status(&fx.router, method, path, Some(&token)).await?), "{method} {path}");
        }
    }
    Ok(())
}


#[tokio::test]
async fn the_document_lists_the_selected_modules_only() -> TestResult {
    let fx = fixture("alerts,cases")?;
    let document = body_json(call(&fx.router, "GET", "/openapi.json", None, Body::empty()).await?).await?;
    let paths = document.get("paths").ok_or("no paths")?;
    assert!(paths.get("/alerts").is_some() && paths.get("/cases").is_some());
    assert!(paths.get("/assets").is_none());
    Ok(())
}
