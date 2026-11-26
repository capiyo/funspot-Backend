use axum::{
    extract::{Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use mongodb::bson::{doc, oid::ObjectId, Document};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{models::user::Claims as UserClaims, state::AppState};

const PLAYBACK_GRANT_TTL_SECONDS: i64 = 14_400;

#[derive(Debug, Serialize, Deserialize)]
struct PlaybackGrantClaims {
    sub: String,
    fixture_id: String,
    stream_id: String,
    iat: usize,
    exp: usize,
    jti: String,
}

/// Issues a short-lived, user- and fixture-scoped grant for the private video
/// gateway. This deliberately does not return an SRS URL: SRS does not validate
/// Funspot grants, so exposing a direct SRS URL here would bypass authorization.
pub async fn issue_playback_grant(
    State(state): State<AppState>,
    Path(fixture_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if fixture_id.is_empty()
        || fixture_id.len() > 128
        || !fixture_id
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Invalid fixture ID" })),
        )
            .into_response();
    }

    let user_secret = match std::env::var("JWT_SECRET") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            tracing::error!("JWT_SECRET is missing; video playback authorization is disabled");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "success": false, "error": "Playback authorization is unavailable" })),
            )
                .into_response();
        }
    };

    let grant_secret = match std::env::var("VIDEO_PLAYBACK_SIGNING_SECRET") {
        Ok(value) if value.len() >= 32 => value,
        _ => {
            tracing::error!("VIDEO_PLAYBACK_SIGNING_SECRET must contain at least 32 bytes");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "success": false, "error": "Playback authorization is unavailable" })),
            )
                .into_response();
        }
    };

    let bearer = match headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
    {
        Some(value) => value,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "success": false, "error": "Authentication required" })),
            )
                .into_response();
        }
    };

    let mut user_validation = Validation::default();
    user_validation.leeway = 5;
    let user_claims = match decode::<UserClaims>(
        bearer,
        &DecodingKey::from_secret(user_secret.as_bytes()),
        &user_validation,
    ) {
        Ok(token) => token.claims,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "success": false, "error": "Invalid or expired session" })),
            )
                .into_response();
        }
    };

    let user_id = match ObjectId::parse_str(&user_claims.sub) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "success": false, "error": "Invalid session subject" })),
            )
                .into_response();
        }
    };

    let users = state.db.collection::<Document>("users");
    match users.find_one(doc! { "_id": user_id }).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "success": false, "error": "User session is no longer active" })),
            )
                .into_response();
        }
        Err(error) => {
            tracing::error!("Video playback user lookup failed: {error}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Unable to authorize playback" })),
            )
                .into_response();
        }
    }

    // Stream records are provisioned only by trusted operations. A live status
    // is insufficient on its own: rights_status must explicitly be authorized.
    let streams = state.db.collection::<Document>("video_streams");
    let stream = match streams
        .find_one(doc! {
            "fixture_id": &fixture_id,
            "status": "live",
            "rights_status": "authorized"
        })
        .await
    {
        Ok(Some(stream)) => stream,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "success": false, "error": "No authorized live stream for this fixture" })),
            )
                .into_response();
        }
        Err(error) => {
            tracing::error!("Video stream registry lookup failed: {error}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Unable to authorize playback" })),
            )
                .into_response();
        }
    };

    let stream_id = match stream.get_str("stream_id") {
        Ok(value) if !value.is_empty() && value.len() <= 128 => value.to_owned(),
        _ => {
            tracing::error!("Live video stream record has no valid stream_id");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "success": false, "error": "Stream is not configured for playback" })),
            )
                .into_response();
        }
    };

    let now = chrono::Utc::now().timestamp();
    let claims = PlaybackGrantClaims {
        sub: user_claims.sub,
        fixture_id,
        stream_id,
        iat: now as usize,
        exp: (now + PLAYBACK_GRANT_TTL_SECONDS) as usize,
        jti: uuid::Uuid::new_v4().to_string(),
    };

    match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(grant_secret.as_bytes()),
    ) {
        Ok(token) => {
            let playback_origin = match std::env::var("VIDEO_PLAYBACK_PUBLIC_ORIGIN") {
                Ok(value) if value.starts_with("https://") || value.starts_with("http://") => {
                    value.trim_end_matches('/').to_owned()
                }
                _ => {
                    tracing::error!("VIDEO_PLAYBACK_PUBLIC_ORIGIN is missing or invalid");
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({ "success": false, "error": "Playback delivery is not configured" })),
                    )
                        .into_response();
                }
            };
            let playback_host = playback_origin
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            let rtc_api_url = format!("{}/rtc/v1/play/", playback_origin);
            let webrtc_url = format!(
                "webrtc://{}/live/{}?token={}",
                playback_host, claims.stream_id, token
            );
            let hls_url = format!(
                "{}/live/{}.m3u8?token={}&stream={}",
                playback_origin, claims.stream_id, token, claims.stream_id
            );
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "grant": token,
                    "token_type": "Bearer",
                    "expires_in": PLAYBACK_GRANT_TTL_SECONDS,
                    "fixture_id": claims.fixture_id,
                    "stream_id": claims.stream_id,
                    "rtc_api_url": rtc_api_url,
                    "webrtc_url": webrtc_url,
                    "hls_url": hls_url
                })),
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!("Failed to sign video playback grant: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Unable to authorize playback" })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorizePlaybackQuery {
    pub stream: Option<String>,
}

/// Validates a short-lived playback grant for the Nginx media edge.
/// The edge calls this for WebRTC signaling and every HLS manifest/segment.
pub async fn authorize_playback(
    State(state): State<AppState>,
    Query(query): Query<AuthorizePlaybackQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let grant_secret = match std::env::var("VIDEO_PLAYBACK_SIGNING_SECRET") {
        Ok(value) if value.len() >= 32 => value,
        _ => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let bearer = match headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
    {
        Some(value) => value,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let mut validation = Validation::default();
    validation.algorithms = vec![jsonwebtoken::Algorithm::HS256];
    validation.leeway = 2;
    let claims = match decode::<PlaybackGrantClaims>(
        bearer,
        &DecodingKey::from_secret(grant_secret.as_bytes()),
        &validation,
    ) {
        Ok(token) => token.claims,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    if claims.fixture_id.is_empty()
        || claims.stream_id.is_empty()
        || query
            .stream
            .as_deref()
            .is_some_and(|stream| stream != claims.stream_id)
    {
        return StatusCode::FORBIDDEN.into_response();
    }

    let user_id = match ObjectId::parse_str(&claims.sub) {
        Ok(value) => value,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let users = state.db.collection::<Document>("users");
    match users.find_one(doc! { "_id": user_id }).await {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::error!("Playback grant user revalidation failed: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    let streams = state.db.collection::<Document>("video_streams");
    match streams
        .find_one(doc! {
            "fixture_id": &claims.fixture_id,
            "stream_id": &claims.stream_id,
            "status": "live",
            "rights_status": "authorized"
        })
        .await
    {
        Ok(Some(_)) => StatusCode::NO_CONTENT.into_response(),
        Ok(None) => StatusCode::FORBIDDEN.into_response(),
        Err(error) => {
            tracing::error!("Playback grant stream revalidation failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
