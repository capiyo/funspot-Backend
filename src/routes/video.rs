use axum::{routing::get, Router};

use crate::{
    handlers::video::{authorize_playback, issue_playback_grant},
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/fixtures/:fixture_id/grant", get(issue_playback_grant))
        .route("/authorize", get(authorize_playback))
}
