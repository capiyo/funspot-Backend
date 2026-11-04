use axum::http::HeaderMap;
use jsonwebtoken::{decode, DecodingKey, Validation};
use mongodb::{bson::{doc, oid::ObjectId}, Collection};

use crate::{
    config::validate_jwt_secret,
    errors::{AppError, Result},
    models::user::Claims,
    state::AppState,
};

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
