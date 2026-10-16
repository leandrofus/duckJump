//! Against a running duckjump-gw: DUCKJUMP_TEST_GATEWAY=http://127.0.0.1:8080
//! and DUCKJUMP_TEST_USER / DUCKJUMP_TEST_PASSWORD of a local user (no TOTP).
//! Skipped when DUCKJUMP_TEST_GATEWAY is not set.

use duckjump_assist_client::{Gateway, SupportRequest};

#[tokio::test]
async fn request_status_and_end_against_a_real_gateway() {
    let Ok(server) = std::env::var("DUCKJUMP_TEST_GATEWAY") else {
        eprintln!("skipped: DUCKJUMP_TEST_GATEWAY not set");
        return;
    };
    let user = std::env::var("DUCKJUMP_TEST_USER").expect("DUCKJUMP_TEST_USER");
    let password = std::env::var("DUCKJUMP_TEST_PASSWORD").expect("DUCKJUMP_TEST_PASSWORD");

    let gw = Gateway::new(&server).unwrap();
    let providers = gw.providers().await.unwrap();
    assert!(providers.local);

    // Anonymous requests are refused.
    let err = gw.request_support(&SupportRequest { reason: "x".into(), ..Default::default() }).await.unwrap_err();
    assert_eq!(err.status, 401, "{err}");
    assert_eq!(gw.me().await.unwrap(), None);

    let err = gw.login(&user, "wrong-password").await.unwrap_err();
    assert_eq!((err.status, err.code.as_str()), (401, "invalid_credentials"));
    let out = gw.login(&user, &password).await.unwrap();
    assert!(!out.mfa_required);
    assert_eq!(gw.me().await.unwrap().unwrap().username, user);

    let req = SupportRequest {
        reason: "VPN no conecta".into(),
        ticket: "INC-1".into(),
        account_type: "ad".into(),
        domain: "CORP".into(),
        hostname: "PC-01".into(),
        client_os: "linux".into(),
        ..Default::default()
    };
    let sess = gw.request_support(&req).await.unwrap();
    assert_eq!(sess.target_name, format!("CORP\\{user}"));
    assert_eq!(sess.verification_code.len(), 6);
    assert_eq!(sess.status, "pending");

    // Status and end work with the token alone (the agent's side).
    let anon = Gateway::new(&server).unwrap();
    let st = anon.support_status(&sess.token).await.unwrap();
    assert_eq!(st.status, "pending");
    assert!(!st.is_over());
    anon.end_support(&sess.token).await.unwrap();
    assert!(anon.support_status(&sess.token).await.unwrap().is_over());
    assert_eq!(anon.support_status("nope").await.unwrap_err().status, 404);

    gw.logout().await.unwrap();
    assert_eq!(gw.me().await.unwrap(), None);
}
