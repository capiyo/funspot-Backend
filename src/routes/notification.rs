use axum::{
    routing::{get, post, put},
    Router,
};
use crate::handlers::notification_handler::{
    register_token,
    unregister_token,
    get_user_notifications,
    mark_notifications_read,
    get_notification_preferences,
    update_notification_preferences,
    get_unread_summary,
};
use crate::state::AppState;

// Only account-scoped operations are mounted here. The legacy send, bulk-send,
// cleanup and token-debug handlers are intentionally not exposed until they
// have explicit service/admin authorization. Mounting them publicly would let
// unauthenticated callers send arbitrary pushes or inspect/alter token state.
pub fn notification_routes() -> Router<AppState> {
    Router::new()
        .route("/register-token", post(register_token))
        .route("/unregister-token", delete(unregister_token))
        .route("/user/:user_id", get(get_user_notifications))
        .route("/mark-read", put(mark_notifications_read))
        .route("/unread-summary/:user_id", get(get_unread_summary))
        .route("/preferences/:user_id", get(get_notification_preferences))
        .route("/preferences", put(update_notification_preferences))
}
