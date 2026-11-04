use crate::{errors::AppError, models::channel::Channel, AppState};
use axum::{extract::{Query, State}, http::HeaderMap, Json};
use bson::{doc, oid::ObjectId, DateTime as BsonDateTime, Document, Bson};
use futures_util::StreamExt;
use mongodb::Collection;
use jsonwebtoken::{decode, DecodingKey, Validation};
use crate::models::user::Claims;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
pub struct PossessionQuery { pub fixture_id: String, pub channel_id: String }
#[derive(Debug, Deserialize)]
pub struct PossessionVoteRequest {
    pub fixture_id: String, pub channel_id: String, pub user_id: String,
    pub username: String, pub selection: String,
}
#[derive(Debug, Deserialize)]
pub struct PossessionPokeRequest {
    pub fixture_id: String, pub channel_id: String, pub user_id: String,
    pub username: String, pub selection: String, pub amount: i32,
}
#[derive(Debug, Deserialize)]
pub struct MatchPossessionPokeRequest {
    pub fixture_id: String, pub channel_id: String, pub poke_id: String, pub user_id: String,
}
#[derive(Debug, Deserialize)]
pub struct PossessionSettlementRequest {
    pub fixture_id: String, pub channel_id: String,
    #[serde(default)] pub settlement_key: Option<String>,
}

fn validate_side(side: &str) -> Result<(), AppError> {
    if side == "home" || side == "away" { Ok(()) }
    else { Err(AppError::ValidationError("Selection must be home or away".into())) }
}
fn id(value: &str) -> Result<ObjectId, AppError> {
    ObjectId::parse_str(value).map_err(|e| AppError::InvalidObjectId(e.to_string()))
}
fn verify_actor(headers: &HeaderMap, user_id: &str) -> Result<(), AppError> {
    let token = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ")).ok_or(AppError::Unauthorized)?;
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());
    let claims = decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default())
        .map_err(|_| AppError::Unauthorized)?.claims;
    if claims.sub == user_id { Ok(()) } else { Err(AppError::Unauthorized) }
}
async fn require_member(state: &AppState, channel_id: &str, user_id: &str, headers: &HeaderMap) -> Result<(), AppError> {
    verify_actor(headers, user_id)?;
    let channels: Collection<Channel> = state.db.collection("channels");
    let channel = channels.find_one(doc! { "channel_id": channel_id }).await.map_err(AppError::MongoDB)?
        .ok_or(AppError::DocumentNotFound)?;
    if channel.members.iter().any(|m| m.user_id == user_id) { Ok(()) }
    else { Err(AppError::Unauthorized) }
}
async fn market_snapshot(state: &AppState, fixture_id: &str, channel_id: &str, viewer: Option<&str>) -> Result<Value, AppError> {
    let votes: Collection<Document> = state.db.collection("possession_votes");
    let pokes: Collection<Document> = state.db.collection("possession_pokes");
    let mut vc = votes.find(doc! { "fixture_id": fixture_id, "channel_id": channel_id }).await.map_err(AppError::MongoDB)?;
    let mut vote_rows = Vec::new(); let mut home = 0_i64; let mut away = 0_i64; let mut user_selection = Value::Null;
    while let Some(row) = vc.next().await {
        let row = row.map_err(AppError::MongoDB)?;
        let selection = row.get_str("selection").unwrap_or("home");
        if selection == "home" { home += 1 } else if selection == "away" { away += 1 }
        if viewer.is_some_and(|u| row.get_str("user_id").ok() == Some(u)) { user_selection = json!(selection); }
        vote_rows.push(json!({
            "id": row.get_object_id("_id").ok().map(|v| v.to_hex()),
            "fixture_id": row.get_str("fixture_id").unwrap_or_default(),
            "channel_id": row.get_str("channel_id").unwrap_or_default(),
            "user_id": row.get_str("user_id").unwrap_or_default(),
            "username": row.get_str("username").unwrap_or("Fan"),
            "selection": selection,
            "created_at": row.get_datetime("created_at").ok().map(|v| v.to_chrono().to_rfc3339()),
        }));
    }
    let mut pc = pokes.find(doc! { "fixture_id": fixture_id, "channel_id": channel_id, "status": { "$in": ["open", "matched"] } }).await.map_err(AppError::MongoDB)?;
    let mut poke_rows = Vec::new();
    while let Some(row) = pc.next().await {
        let row = row.map_err(AppError::MongoDB)?;
        let stake = row.get_i32("amount").unwrap_or(0);
        let finisher_amount = row.get_i32("finisher_amount").ok();
        poke_rows.push(json!({
            "id": row.get_object_id("_id").ok().map(|v| v.to_hex()),
            "fixture_id": fixture_id, "channel_id": channel_id,
            "user_id": row.get_str("user_id").unwrap_or_default(),
            "username": row.get_str("username").unwrap_or("Fan"),
            "selection": row.get_str("selection").unwrap_or("home"),
            "amount": stake, "stake": stake,
            "status": row.get_str("status").unwrap_or("open"),
            "created_at": row.get_datetime("created_at").ok().map(|v| v.to_chrono().to_rfc3339()),
            "finisher_id": row.get_str("finisher_id").ok(),
            "finisher_name": row.get_str("finisher_name").ok(),
            "finisher_selection": row.get_str("finisher_selection").ok(),
            "finisher_amount": finisher_amount,
            "total_pot": stake + finisher_amount.unwrap_or(0),
            "settled_at": row.get_datetime("settled_at").ok().map(|v| v.to_chrono().to_rfc3339()),
        }));
    }
    let market = state.db.collection::<Document>("possession_markets")
        .find_one(doc! { "fixture_id": fixture_id, "channel_id": channel_id }).await.map_err(AppError::MongoDB)?;
    Ok(json!({
        "fixture_id": fixture_id, "channel_id": channel_id,
        "status": market.as_ref().and_then(|m| m.get_str("status").ok()).unwrap_or("open"),
        "home_possession": market.as_ref().and_then(|m| m.get_f64("home_possession").ok()),
        "away_possession": market.as_ref().and_then(|m| m.get_f64("away_possession").ok()),
        "home_votes": home, "away_votes": away, "user_selection": user_selection,
        "votes": vote_rows, "pokes": poke_rows,
        "settlement": market.and_then(|m| m.get("settlement").cloned()),
    }))
}

pub async fn get_possession_market(State(state): State<AppState>, Query(q): Query<PossessionQuery>) -> Result<Json<Value>, AppError> {
    let data = market_snapshot(&state, &q.fixture_id, &q.channel_id, None).await?;
    Ok(Json(json!({ "success": true, "market": data })))
}
pub async fn get_possession_votes(State(state): State<AppState>, Query(q): Query<PossessionQuery>) -> Result<Json<Value>, AppError> {
    let data = market_snapshot(&state, &q.fixture_id, &q.channel_id, None).await?;
    Ok(Json(json!({ "success": true, "votes": data["votes"] })))
}
pub async fn get_possession_pokes(State(state): State<AppState>, Query(q): Query<PossessionQuery>) -> Result<Json<Value>, AppError> {
    let data = market_snapshot(&state, &q.fixture_id, &q.channel_id, None).await?;
    Ok(Json(json!({ "success": true, "pokes": data["pokes"] })))
}
pub async fn cast_possession_vote(State(state): State<AppState>, headers: HeaderMap, Json(p): Json<PossessionVoteRequest>) -> Result<Json<Value>, AppError> {
    validate_side(&p.selection)?; require_member(&state, &p.channel_id, &p.user_id, &headers).await?;
    let users: Collection<Document> = state.db.collection("users");
    let user = users.find_one(doc! { "_id": id(&p.user_id)? }).await.map_err(AppError::MongoDB)?.ok_or(AppError::UserNotFound)?;
    let username = user.get_str("username").unwrap_or(&p.username).to_string();
    let votes: Collection<Document> = state.db.collection("possession_votes");
    let now = BsonDateTime::now();
    let existing = votes.find_one(doc! { "fixture_id": &p.fixture_id, "channel_id": &p.channel_id, "user_id": &p.user_id }).await.map_err(AppError::MongoDB)?;
    if existing.is_some() { return Err(AppError::ValidationError("You have already voted on possession for this fixture".into())); }
    let result = votes.insert_one(doc! {
        "fixture_id": &p.fixture_id, "channel_id": &p.channel_id, "user_id": &p.user_id,
        "username": username, "selection": &p.selection, "created_at": now,
    }).await.map_err(AppError::MongoDB)?;
    let vote_id = result.inserted_id.as_object_id().map(|v| v.to_hex()).unwrap_or_default();
    let market = state.db.collection::<Document>("possession_markets");
    market.update_one(doc! { "fixture_id": &p.fixture_id, "channel_id": &p.channel_id },
        doc! { "$setOnInsert": { "fixture_id": &p.fixture_id, "channel_id": &p.channel_id, "status": "open", "created_at": now } })
        .upsert(true).await.map_err(AppError::MongoDB)?;
    let data = market_snapshot(&state, &p.fixture_id, &p.channel_id, Some(&p.user_id)).await?;
    Ok(Json(json!({ "success": true, "message": "Possession vote recorded", "vote": {
        "id": vote_id, "user_id": p.user_id, "username": username, "selection": p.selection, "created_at": now.to_chrono().to_rfc3339()
    }, "market": data })))
}
pub async fn create_possession_poke(State(state): State<AppState>, headers: HeaderMap, Json(p): Json<PossessionPokeRequest>) -> Result<Json<Value>, AppError> {
    validate_side(&p.selection)?; require_member(&state, &p.channel_id, &p.user_id, &headers).await?;
    if p.amount < 5 { return Err(AppError::ValidationError("Minimum possession poke is 5 points".into())); }
    let user_oid = id(&p.user_id)?;
    let users: Collection<Document> = state.db.collection("users");
    let mut session = state.client.start_session().await.map_err(AppError::MongoDB)?;
    session.start_transaction().await.map_err(AppError::MongoDB)?;
    let debit = users.update_one(doc! { "_id": user_oid, "season_points": { "$gte": p.amount } }, doc! { "$inc": { "season_points": -p.amount } }).session(&mut session).await.map_err(AppError::MongoDB)?;
    if debit.matched_count == 0 { session.abort_transaction().await.map_err(AppError::MongoDB)?; return Err(AppError::ValidationError("Insufficient season points".into())); }
    let channels: Collection<Document> = state.db.collection("channels");
    channels.update_many(doc! { "members.user_id": &p.user_id }, doc! { "$inc": { "members.$[m].season_points": -p.amount } })
        .array_filters(vec![doc! { "m.user_id": &p.user_id }]).session(&mut session).await.map_err(AppError::MongoDB)?;
    let pokes: Collection<Document> = state.db.collection("possession_pokes");
    let now = BsonDateTime::now();
    let inserted = pokes.insert_one(doc! {
        "fixture_id": &p.fixture_id, "channel_id": &p.channel_id, "user_id": &p.user_id,
        "username": &p.username, "selection": &p.selection, "amount": p.amount,
        "status": "open", "created_at": now,
    }).session(&mut session).await.map_err(AppError::MongoDB)?;
    let markets: Collection<Document> = state.db.collection("possession_markets");
    markets.update_one(doc! { "fixture_id": &p.fixture_id, "channel_id": &p.channel_id },
        doc! { "$setOnInsert": { "fixture_id": &p.fixture_id, "channel_id": &p.channel_id, "status": "open", "created_at": now } })
        .upsert(true).session(&mut session).await.map_err(AppError::MongoDB)?;
    session.commit_transaction().await.map_err(AppError::MongoDB)?;
    let poke_id = inserted.inserted_id.as_object_id().map(|v| v.to_hex()).unwrap_or_default();
    let data = market_snapshot(&state, &p.fixture_id, &p.channel_id, Some(&p.user_id)).await?;
    Ok(Json(json!({ "success": true, "message": "Possession poke created", "poke": {
        "id": poke_id, "user_id": p.user_id, "username": p.username, "selection": p.selection,
        "amount": p.amount, "status": "open", "created_at": now.to_chrono().to_rfc3339()
    }, "market": data })))
}
pub async fn match_possession_poke(State(state): State<AppState>, headers: HeaderMap, Json(p): Json<MatchPossessionPokeRequest>) -> Result<Json<Value>, AppError> {
    require_member(&state, &p.channel_id, &p.user_id, &headers).await?;
    let poke_oid = id(&p.poke_id)?; let user_oid = id(&p.user_id)?;
    let pokes: Collection<Document> = state.db.collection("possession_pokes");
    let users: Collection<Document> = state.db.collection("users");
    let channels: Collection<Document> = state.db.collection("channels");
    let mut session = state.client.start_session().await.map_err(AppError::MongoDB)?;
    session.start_transaction().await.map_err(AppError::MongoDB)?;
    let starter = pokes.find_one(doc! { "_id": poke_oid, "fixture_id": &p.fixture_id, "channel_id": &p.channel_id, "status": "open" }).session(&mut session).await.map_err(AppError::MongoDB)?.ok_or(AppError::DocumentNotFound)?;
    let starter_id = starter.get_str("user_id").unwrap_or_default().to_string();
    if starter_id == p.user_id { session.abort_transaction().await.map_err(AppError::MongoDB)?; return Err(AppError::ValidationError("You cannot match your own poke".into())); }
    let side = starter.get_str("selection").unwrap_or("home").to_string();
    let opposite = if side == "home" { "away" } else { "home" };
    let stake = starter.get_i32("amount").unwrap_or(0);
    let debit = users.update_one(doc! { "_id": user_oid, "season_points": { "$gte": stake } }, doc! { "$inc": { "season_points": -stake } }).session(&mut session).await.map_err(AppError::MongoDB)?;
    if debit.matched_count == 0 { session.abort_transaction().await.map_err(AppError::MongoDB)?; return Err(AppError::ValidationError("Insufficient season points".into())); }
    channels.update_many(doc! { "members.user_id": &p.user_id }, doc! { "$inc": { "members.$[m].season_points": -stake } }).array_filters(vec![doc! { "m.user_id": &p.user_id }]).session(&mut session).await.map_err(AppError::MongoDB)?;
    let finisher = users.find_one(doc! { "_id": user_oid }).session(&mut session).await.map_err(AppError::MongoDB)?.ok_or(AppError::UserNotFound)?;
    let finisher_name = finisher.get_str("username").unwrap_or("Fan").to_string();
    let update = pokes.update_one(doc! { "_id": poke_oid, "status": "open", "selection": side }, doc! {
        "$set": { "status": "matched", "finisher_id": &p.user_id, "finisher_name": &finisher_name,
        "finisher_selection": opposite, "finisher_amount": stake, "matched_at": BsonDateTime::now() }
    }).session(&mut session).await.map_err(AppError::MongoDB)?;
    if update.modified_count == 0 { session.abort_transaction().await.map_err(AppError::MongoDB)?; return Err(AppError::ValidationError("Poke was already matched".into())); }
    session.commit_transaction().await.map_err(AppError::MongoDB)?;
    let data = market_snapshot(&state, &p.fixture_id, &p.channel_id, Some(&p.user_id)).await?;
    Ok(Json(json!({ "success": true, "message": "Possession poke matched", "market": data })))
}
pub async fn settle_possession_market(State(state): State<AppState>, Json(p): Json<PossessionSettlementRequest>) -> Result<Json<Value>, AppError> {
    let configured_key = std::env::var("POSSESSION_SETTLEMENT_KEY").map_err(|_| AppError::ServiceUnavailable("Possession settlement is not configured".into()))?;
    if configured_key.is_empty() || p.settlement_key.as_deref() != Some(configured_key.as_str()) {
        return Err(AppError::Unauthorized);
    }
    let games: Collection<Document> = state.db.collection("games");
    let game = games.find_one(doc! { "matchId": &p.fixture_id }).await.map_err(AppError::MongoDB)?.ok_or(AppError::DocumentNotFound)?;
    let stats = game.get_array("statistics").map_err(|_| AppError::ValidationError("No possession statistics are available yet".into()))?;
    let latest = stats.last().and_then(Bson::as_document).ok_or(AppError::ValidationError("No final possession statistics are available yet".into()))?;
    let teams = latest.get_document("statistics").map_err(|_| AppError::ValidationError("Possession statistics are incomplete".into()))?;
    let home = teams.get_document("home").ok().and_then(|d| d.get_f64("possession").ok());
    let away = teams.get_document("away").ok().and_then(|d| d.get_f64("possession").ok());
    let (home, away) = match (home, away) { (Some(h), Some(a)) if h.is_finite() && a.is_finite() => (h,a), _ => return Err(AppError::ValidationError("Final home and away possession statistics are not available".into())) };
    if !matches!(game.get_str("status").unwrap_or("").to_lowercase().as_str(), "finished" | "ft" | "full time" | "full_time") {
        return Err(AppError::ValidationError("Possession can only be settled after the match is complete".into()));
    }
    let winner = if home > away { "home" } else if away > home { "away" } else { "draw" };
    let market_col: Collection<Document> = state.db.collection("possession_markets");
    let claim = market_col.update_one(
        doc! { "fixture_id": &p.fixture_id, "channel_id": &p.channel_id, "status": { "$nin": ["settled", "settling"] } },
        doc! { "$set": { "status": "settling", "home_possession": home, "away_possession": away } }
    ).await.map_err(AppError::MongoDB)?;
    if claim.matched_count == 0 {
        return Err(AppError::ValidationError("Possession market is already settling or settled".into()));
    }
    let pokes: Collection<Document> = state.db.collection("possession_pokes");
    let mut cursor = pokes.find(doc! { "fixture_id": &p.fixture_id, "channel_id": &p.channel_id, "status": "matched" }).await.map_err(AppError::MongoDB)?;
    while let Some(row) = cursor.next().await {
        let row = row.map_err(AppError::MongoDB)?; let stake = row.get_i32("amount").unwrap_or(0);
        let starter_side = row.get_str("selection").unwrap_or(""); let finisher_side = row.get_str("finisher_selection").unwrap_or("");
        let starter_id = row.get_str("user_id").unwrap_or(""); let finisher_id = row.get_str("finisher_id").unwrap_or("");
        let (winner_id, starter_result, finisher_result) = if winner == "draw" {
            (None, "refunded", "refunded")
        } else if starter_side == winner { (Some(starter_id), "won", "lost") } else if finisher_side == winner { (Some(finisher_id), "lost", "won") } else { (None, "refunded", "refunded") };
        let mut session = state.client.start_session().await.map_err(AppError::MongoDB)?; session.start_transaction().await.map_err(AppError::MongoDB)?;
        let users: Collection<Document> = state.db.collection("users"); let channels: Collection<Document> = state.db.collection("channels");
        if let Some(winner_id) = winner_id {
            let oid = id(winner_id)?;
            users.update_one(doc! { "_id": oid }, doc! { "$inc": { "season_points": stake * 2 } }).session(&mut session).await.map_err(AppError::MongoDB)?;
            channels.update_many(doc! { "members.user_id": winner_id }, doc! { "$inc": { "members.$[m].season_points": stake * 2 } }).array_filters(vec![doc! { "m.user_id": winner_id }]).session(&mut session).await.map_err(AppError::MongoDB)?;
        } else {
            for uid in [starter_id, finisher_id] {
                let oid = id(uid)?;
                users.update_one(doc! { "_id": oid }, doc! { "$inc": { "season_points": stake } }).session(&mut session).await.map_err(AppError::MongoDB)?;
                channels.update_many(doc! { "members.user_id": uid }, doc! { "$inc": { "members.$[m].season_points": stake } }).array_filters(vec![doc! { "m.user_id": uid }]).session(&mut session).await.map_err(AppError::MongoDB)?;
            }
        }
        pokes.update_one(doc! { "_id": row.get_object_id("_id").map_err(|_| AppError::DocumentNotFound)?, "status": "matched" }, doc! { "$set": {
            "status": if winner == "draw" || winner_id.is_none() { "refunded" } else { "settled" },
            "winner_id": winner_id, "starter_result": starter_result, "finisher_result": finisher_result, "settled_at": BsonDateTime::now()
        }}).session(&mut session).await.map_err(AppError::MongoDB)?;
        session.commit_transaction().await.map_err(AppError::MongoDB)?;
    }
    let mut open_cursor = pokes.find(doc! { "fixture_id": &p.fixture_id, "channel_id": &p.channel_id, "status": "open" }).await.map_err(AppError::MongoDB)?;
    while let Some(open_row) = open_cursor.next().await {
        let open_row = open_row.map_err(AppError::MongoDB)?;
        let starter_id = open_row.get_str("user_id").unwrap_or_default();
        let stake = open_row.get_i32("amount").unwrap_or(0);
        let oid = id(starter_id)?;
        let mut session = state.client.start_session().await.map_err(AppError::MongoDB)?;
        session.start_transaction().await.map_err(AppError::MongoDB)?;
        let users: Collection<Document> = state.db.collection("users");
        let channels: Collection<Document> = state.db.collection("channels");
        users.update_one(doc! { "_id": oid }, doc! { "$inc": { "season_points": stake } }).session(&mut session).await.map_err(AppError::MongoDB)?;
        channels.update_many(doc! { "members.user_id": starter_id }, doc! { "$inc": { "members.$[m].season_points": stake } }).array_filters(vec![doc! { "m.user_id": starter_id }]).session(&mut session).await.map_err(AppError::MongoDB)?;
        pokes.update_one(doc! { "_id": open_row.get_object_id("_id").map_err(|_| AppError::DocumentNotFound)?, "status": "open" }, doc! { "$set": { "status": "refunded", "starter_result": "unmatched", "settled_at": BsonDateTime::now() } }).session(&mut session).await.map_err(AppError::MongoDB)?;
        session.commit_transaction().await.map_err(AppError::MongoDB)?;
    }
    market_col.update_one(doc! { "fixture_id": &p.fixture_id, "channel_id": &p.channel_id, "status": "settling" },
        doc! { "$set": { "status": "settled", "home_possession": home, "away_possession": away,
        "settlement": { "winner": winner, "home_possession": home, "away_possession": away, "settled_at": BsonDateTime::now() } } })
        .await.map_err(AppError::MongoDB)?;
    let data = market_snapshot(&state, &p.fixture_id, &p.channel_id, None).await?;
    Ok(Json(json!({ "success": true, "message": "Possession market settled", "market": data })))
}
