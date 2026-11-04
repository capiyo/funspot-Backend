use axum::http::HeaderMap;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use mongodb::{bson::{doc, oid::ObjectId}, Collection};
use serde::Deserialize;
use std::{sync::OnceLock, time::{Duration, Instant}};
use tokio::sync::RwLock;

use crate::{
    config::validate_jwt_secret,
    errors::{AppError, Result},
    models::user::Claims,
    state::AppState,
};


const FIREBASE_JWKS_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const FIREBASE_JWKS_TTL: Duration = Duration::from_secs(60 * 60);

struct CachedFirebaseJwks {
    keys: JwkSet,
    expires_at: Instant,
}

static FIREBASE_JWKS_CACHE: OnceLock<RwLock<Option<CachedFirebaseJwks>>> = OnceLock::new();

fn firebase_jwks_cache() -> &'static RwLock<Option<CachedFirebaseJwks>> {
    FIREBASE_JWKS_CACHE.get_or_init(|| RwLock::new(None))
}

#[derive(Debug, Deserialize)]
struct FirebasePhoneClaims {
    sub: String,
    exp: usize,
    phone_number: Option<String>,
}

/// Validate a Firebase Phone Auth ID token and bind it to the phone number
/// being registered, checked, or exchanged for a backend session. Google's
/// rotating Secure Token public keys are cached for one hour.
pub async fn verify_firebase_phone_token(headers: &HeaderMap, expected_phone: &str) -> Result<()> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or(AppError::AuthError)?;

    let header = decode_header(token).map_err(|_| AppError::AuthError)?;
    if header.alg != Algorithm::RS256 {
        return Err(AppError::AuthError);
    }
    let kid = header.kid.as_deref().ok_or(AppError::AuthError)?;

    let decoding_key = {
        let cache = firebase_jwks_cache();
        {
            let cached = cache.read().await;
            if let Some(cached) = cached.as_ref().filter(|entry| entry.expires_at > Instant::now()) {
                let jwk = cached.keys.find(kid).ok_or(AppError::AuthError)?;
                DecodingKey::from_jwk(jwk).map_err(|_| AppError::AuthError)?
            } else {
                drop(cached);
                let response = reqwest::Client::new()
                    .get(FIREBASE_JWKS_URL)
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await
                    .map_err(|error| AppError::InternalServerError(format!(
                        "Firebase signing-key request failed: {}", error
                    )))?
                    .error_for_status()
                    .map_err(|error| AppError::InternalServerError(format!(
                        "Firebase signing-key response failed: {}", error
                    )))?;
                let keys: JwkSet = response.json().await.map_err(|error| {
                    AppError::InternalServerError(format!(
                        "Firebase signing-key response was invalid: {}", error
                    ))
                })?;
                let jwk = keys.find(kid).ok_or(AppError::AuthError)?;
                let key = DecodingKey::from_jwk(jwk).map_err(|_| AppError::AuthError)?;
                *cache.write().await = Some(CachedFirebaseJwks {
                    keys,
                    expires_at: Instant::now() + FIREBASE_JWKS_TTL,
                });
                key
            }
        }
    };

    let project_id = std::env::var("FIREBASE_PROJECT_ID")
        .unwrap_or_else(|_| "funzy-d56d7".to_string());
    let issuer = format!("https://securetoken.google.com/{}", project_id);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[project_id.as_str()]);
    validation.set_issuer(&[issuer.as_str()]);
    let claims = decode::<FirebasePhoneClaims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::AuthError)?
        .claims;

    if claims.sub.is_empty() || claims.exp == 0 {
        return Err(AppError::AuthError);
    }
    let token_phone = claims.phone_number.ok_or(AppError::AuthError)?;
    if normalize_phone(&token_phone) != normalize_phone(expected_phone) {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

fn normalize_phone(phone: &str) -> String {
    let mut digits: String = phone.chars().filter(|character| character.is_ascii_digit()).collect();
    if digits.starts_with('0') {
        digits.remove(0);
    }
    if digits.len() > 9 {
        digits = digits[digits.len() - 9..].to_string();
    }
    digits
}

/// Decode the HS256 bearer token issued by the existing login handlers.
/// Authentication always fails closed when the signing secret is invalid.
pub fn authenticated_claims(headers: &HeaderMap) -> Result<Claims> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or(AppError::AuthError)?;

    let secret = std::env::var("JWT_SECRET")
        .map_err(|_| AppError::ConfigurationError("JWT_SECRET is not configured".to_string()))?;
    validate_jwt_secret(&secret)
        .map_err(|message| AppError::ConfigurationError(message.to_string()))?;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|token| token.claims)
    .map_err(|_| AppError::AuthError)
}

pub(crate) fn authorize_claim_subject(claims: &Claims, user_id: &str) -> Result<()> {
    if claims.sub != user_id {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

pub fn authorize_user(headers: &HeaderMap, user_id: &str) -> Result<()> {
    let claims = authenticated_claims(headers)?;
    authorize_claim_subject(&claims, user_id)
}

/// Operational notification endpoints require a live admin role from MongoDB;
/// a user-supplied flag or a stale JWT claim is never sufficient.
pub async fn authorize_admin(state: &AppState, headers: &HeaderMap) -> Result<()> {
    let claims = authenticated_claims(headers)?;
    let user_id = ObjectId::parse_str(&claims.sub)
        .map_err(|_| AppError::AuthError)?;
    let users: Collection<mongodb::bson::Document> = state.db.collection("users");
    let admin = users
        .find_one(doc! { "_id": user_id, "is_admin": true })
        .await
        .map_err(|error| AppError::InternalServerError(format!("Database error: {}", error)))?;
    if admin.is_none() {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

#[cfg(test)]
mod authorization_tests {
    use super::authorize_claim_subject;
    use crate::models::user::Claims;

    fn claims(subject: &str) -> Claims {
        Claims {
            sub: subject.to_string(),
            username: "test-user".to_string(),
            phone: "700000000".to_string(),
            exp: (chrono::Utc::now().timestamp() + 60) as usize,
        }
    }

    #[test]
    fn user_can_only_access_own_resources() {
        assert!(authorize_claim_subject(&claims("user-a"), "user-a").is_ok());
        assert!(authorize_claim_subject(&claims("user-a"), "user-b").is_err());
    }
}
