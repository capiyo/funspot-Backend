use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post, put},
    Router,
};

use crate::handlers::user_profile::{
    get_user_profiles, get_user_profile_by_id, get_user_profile_by_phone,
    save_user_profile, update_user_balance, get_user_stats,
    get_recent_users, create_user_profile, upload_profile_avatar
};
use crate::state::AppState;

pub fn user_profile_routes() -> Router<AppState> {
    Router::new()
        .route("/profiles", get(get_user_profiles))
        .route("/profile/:id", get(get_user_profile_by_id))
        .route("/profile/:id/avatar", post(upload_profile_avatar).layer(DefaultBodyLimit::max(8 * 1024 * 1024 + 64 * 1024)))
        .route("/profile/phone/:phone", get(get_user_profile_by_phone))
        .route("/profile/stats", get(get_user_stats))
        .route("/profile/recent", get(get_recent_users))
        .route("/create_profile", post(create_user_profile))
        .route("/update-balance", post(update_user_balance))
        .route("/profiles/:id", put(save_user_profile))
}