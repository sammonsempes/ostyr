use crate::fixture::{body_json, call, fixture, fixture_with_permits, login, ANALYST, READER};
use crate::types::TestResult;
use axum::body::Body;
use axum::http::StatusCode;
use platform::merge::MAX_MODULES_CHARS;
use std::sync::Arc;
use tokio::sync::Semaphore;


const ALL_MODULES: &str = "alerts,cases,cmdb,risk,hunts,certificates,oncall,dhcp";


const ROUTES: [(&str, &str); 8] = [
    ("/alerts", "alerts"),
    ("/cases", "cases"),
    ("/assets", "cmdb"),
    ("/risk/entities", "risk"),
    ("/hunts/findings", "hunts"),
    ("/certificates", "certificates"),
    ("/oncall/alerts", "oncall"),
    ("/dhcp/leases/at", "dhcp"),
];


const FINGERPRINT_PATH: &str = "/certificates/0000000000000000000000000000000000000000000000000000000000000000";


const DHCP_QUERIES: [&str; 2] = [
    "/dhcp/leases/at?address=192.0.2.1&at=1700000000",
    "/dhcp/leases/mac?mac=00:11:22:33:44:55&from=1700000000&to=1700003600",
];


const NEW_PATHS: [&str; 5] = ["/hunts/findings", "/certificates", FINGERPRINT_PATH, "/oncall/alerts", "/oncall/alerts/1"];


async fn status(router: &axum::Router, method: &str, path: &str, token: Option<&str>) -> Result<StatusCode, crate::types::TestError> {
    Ok(call(router, method, path, token, Body::empty()).await?.status())
}


fn denied(code: StatusCode) -> bool {
    code == StatusCode::UNAUTHORIZED || code == StatusCode::FORBIDDEN
}


#[tokio::test]
async fn one_session_reaches_every_selected_module() -> TestResult {
    let fx = fixture(ALL_MODULES)?;
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
    let fx = fixture(ALL_MODULES)?;
    let token = login(&fx.router, READER).await?;
    for (path, module) in ROUTES {
        let code = status(&fx.router, "GET", path, Some(&token)).await?;
        if module == "hunts" {
            assert!(!denied(code) && code != StatusCode::NOT_FOUND, "{path} {code}");
        } else {
            assert_eq!(code, StatusCode::FORBIDDEN, "{path}");
        }
    }
    assert_eq!(status(&fx.router, "GET", FINGERPRINT_PATH, Some(&token)).await?, StatusCode::FORBIDDEN);
    assert_eq!(status(&fx.router, "GET", "/oncall/alerts/1", Some(&token)).await?, StatusCode::FORBIDDEN);
    Ok(())
}


#[tokio::test]
async fn the_new_detail_routes_are_mounted_for_an_analyst() -> TestResult {
    for path in NEW_PATHS {
        let fx = fixture(ALL_MODULES)?;
        let token = login(&fx.router, ANALYST).await?;
        let code = status(&fx.router, "GET", path, Some(&token)).await?;
        assert!(!denied(code) && code != StatusCode::NOT_FOUND, "{path} {code}");
        assert_eq!(status(&fx.router, "GET", path, None).await?, StatusCode::UNAUTHORIZED, "{path}");
        for method in ["HEAD", "PUT", "POST", "DELETE"] {
            assert!(denied(status(&fx.router, method, path, Some(&token)).await?), "{method} {path}");
        }
    }
    Ok(())
}


#[tokio::test]
async fn the_new_modules_share_one_semaphore_and_answer_429_when_it_is_empty() -> TestResult {
    let permits = Arc::new(Semaphore::new(0));
    let fx = fixture_with_permits(ALL_MODULES, &permits)?;
    let token = login(&fx.router, ANALYST).await?;
    for path in NEW_PATHS {
        assert_eq!(
            status(&fx.router, "GET", path, Some(&token)).await?,
            StatusCode::TOO_MANY_REQUESTS,
            "{path}"
        );
    }
    Ok(())
}


#[tokio::test]
async fn the_dhcp_routes_share_the_semaphore_and_answer_429_when_it_is_empty() -> TestResult {
    let permits = Arc::new(Semaphore::new(0));
    let fx = fixture_with_permits(ALL_MODULES, &permits)?;
    let token = login(&fx.router, ANALYST).await?;
    for path in DHCP_QUERIES {
        assert_eq!(
            status(&fx.router, "GET", path, Some(&token)).await?,
            StatusCode::TOO_MANY_REQUESTS,
            "{path}"
        );
    }
    Ok(())
}


#[tokio::test]
async fn the_longest_module_list_is_served_and_the_document_lists_every_path() -> TestResult {
    assert!(ALL_MODULES.len() <= MAX_MODULES_CHARS);
    let fx = fixture(ALL_MODULES)?;
    let document = body_json(call(&fx.router, "GET", "/openapi.json", None, Body::empty()).await?).await?;
    let paths = document.get("paths").ok_or("no paths")?;
    for (path, _module) in ROUTES {
        assert!(paths.get(path).is_some(), "{path}");
    }
    Ok(())
}


#[tokio::test]
async fn an_unselected_module_is_denied_by_default() -> TestResult {
    let fx = fixture("alerts")?;
    let token = login(&fx.router, ANALYST).await?;
    assert!(!denied(status(&fx.router, "GET", "/alerts", Some(&token)).await?));
    for path in [
        "/cases",
        "/cases/abc",
        "/assets",
        "/assets/abc",
        "/risk/entities",
        "/risk/entities/host/web01",
        "/hunts/findings",
        "/certificates",
        "/certificates/abc",
        "/oncall/alerts",
        "/oncall/alerts/abc",
        "/dhcp/leases/at",
        "/dhcp/leases/mac",
    ] {
        assert_eq!(status(&fx.router, "GET", path, Some(&token)).await?, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(status(&fx.router, "GET", path, None).await?, StatusCode::UNAUTHORIZED, "{path}");
    }
    Ok(())
}


#[tokio::test]
async fn other_methods_are_denied_on_every_module_route() -> TestResult {
    for (path, _module) in ROUTES {
        let fx = fixture(ALL_MODULES)?;
        let token = login(&fx.router, ANALYST).await?;
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


#[tokio::test]
async fn risk_alone_is_mounted_and_an_unknown_risk_path_is_404() -> TestResult {
    let fx = fixture("risk")?;
    let token = login(&fx.router, ANALYST).await?;
    let code = status(&fx.router, "GET", "/risk/entities", Some(&token)).await?;
    assert!(!denied(code) && code != StatusCode::NOT_FOUND, "{code}");
    assert_eq!(
        status(&fx.router, "GET", "/risk/entities/nokind/x", Some(&token)).await?,
        StatusCode::NOT_FOUND
    );
    assert_eq!(status(&fx.router, "GET", "/alerts", Some(&token)).await?, StatusCode::FORBIDDEN);
    let reader = login(&fx.router, READER).await?;
    assert_eq!(status(&fx.router, "GET", "/risk/entities", Some(&reader)).await?, StatusCode::FORBIDDEN);
    Ok(())
}


#[tokio::test]
async fn the_document_lists_the_risk_paths_when_selected() -> TestResult {
    let fx = fixture("alerts,risk")?;
    let document = body_json(call(&fx.router, "GET", "/openapi.json", None, Body::empty()).await?).await?;
    let paths = document.get("paths").ok_or("no paths")?;
    assert!(paths.get("/risk/entities").is_some() && paths.get("/alerts").is_some());
    Ok(())
}
