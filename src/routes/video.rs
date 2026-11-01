use axum::{routing::get, Router};

use crate::{handlers::video::issue_playback_grant, state::AppState};

pub fn routes() -> Router<AppState> {
    Router::new().route("/fixtures/:fixture_id/grant", get(issue_playback_grant))
}
