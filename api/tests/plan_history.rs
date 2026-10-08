use chrono::{Duration, Utc};
use fira_api::{db, error::ApiError, plan_history::read_plan, seed};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn fixture(pool: &PgPool) {
    let mut tx = pool.begin().await.unwrap();
    seed::seed_all(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
}

fn narrow(value: Value, fields: &[&str]) -> Value {
    let mut map = value.as_object().unwrap().clone();
    map.retain(|key, _| fields.contains(&key.as_str()));
    Value::Object(map)
}

fn sorted(mut values: Vec<Value>) -> Vec<Value> {
    values.sort_by_key(|v| v["id"].as_str().unwrap().to_owned());
    values
}

#[sqlx::test]
async fn replay_now_matches_live_entities_for_every_seeded_project(pool: PgPool) {
    fixture(&pool).await;
    let user = seed::primary_user_id();
    let ws = seed::id(seed::TEAM_WORKSPACE_SLUG);
    for project in db::project_scope(&pool, user, ws).await.unwrap() {
        let history = read_plan(&pool, user, ws, project, None).await.unwrap();
        let live_tracks = db::list_tracks_in_scope(&pool, &[project]).await.unwrap();
        let live_sprints = db::list_sprints_in_scope(&pool, &[project]).await.unwrap();
        let live_tasks = db::list_tasks_in_scope(&pool, &[project]).await.unwrap();
        let track_fields = ["id", "project_id", "title", "color", "sort_key"];
        let sprint_fields = [
            "id",
            "project_id",
            "track_id",
            "title",
            "starts_on",
            "ends_on",
            "sort_key",
        ];
        let task_fields = [
            "id",
            "project_id",
            "track_id",
            "sprint_id",
            "title",
            "section",
            "status",
            "sort_key",
            "created_at",
        ];
        for (replayed, live, fields) in [
            (
                serde_json::to_value(&history.state.tracks).unwrap(),
                serde_json::to_value(live_tracks).unwrap(),
                track_fields.as_slice(),
            ),
            (
                serde_json::to_value(&history.state.sprints).unwrap(),
                serde_json::to_value(live_sprints).unwrap(),
                sprint_fields.as_slice(),
            ),
            (
                serde_json::to_value(&history.state.tasks).unwrap(),
                serde_json::to_value(live_tasks).unwrap(),
                task_fields.as_slice(),
            ),
        ] {
            let live = live
                .as_array()
                .unwrap()
                .iter()
                .cloned()
                .map(|v| narrow(v, fields))
                .collect();
            assert_eq!(
                sorted(
                    replayed
                        .as_array()
                        .unwrap()
                        .iter()
                        .cloned()
                        .map(|v| narrow(v, fields))
                        .collect()
                ),
                sorted(live),
                "project {project}, fields {fields:?}"
            );
        }
    }
}

#[sqlx::test]
async fn history_clamps_to_genesis_and_resurrects_deleted_work(pool: PgPool) {
    fixture(&pool).await;
    let user = seed::primary_user_id();
    let ws = seed::id(seed::TEAM_WORKSPACE_SLUG);
    let project = seed::id("p_atlas");
    let live = read_plan(&pool, user, ws, project, None).await.unwrap();
    let genesis = live.genesis.unwrap();
    let clamped = read_plan(
        &pool,
        user,
        ws,
        project,
        Some(genesis - Duration::weeks(100)),
    )
    .await
    .unwrap();
    assert_eq!(clamped.at, genesis);
    assert!(!clamped.state.tracks.is_empty());
    let dropped = seed::id("t_atlas_dropped");
    assert!(!live.state.tasks.iter().any(|t| t.id == dropped));
    let deleted_at: chrono::DateTime<Utc> = sqlx::query_scalar(
        "SELECT applied_at FROM processed_ops WHERE project_id = $1 AND kind = 'task.delete' AND payload->>'task_id' = $2",
    ).bind(project).bind(dropped.to_string()).fetch_one(&pool).await.unwrap();
    let before = read_plan(
        &pool,
        user,
        ws,
        project,
        Some(deleted_at - Duration::seconds(1)),
    )
    .await
    .unwrap();
    assert_eq!(
        before
            .state
            .tasks
            .iter()
            .find(|t| t.id == dropped)
            .unwrap()
            .title,
        "Retire the v1 metrics pipeline"
    );
    let future = read_plan(
        &pool,
        user,
        ws,
        project,
        Some(Utc::now() + Duration::weeks(100)),
    )
    .await
    .unwrap();
    assert!(future.at <= Utc::now());
    assert!(future.changes.iter().all(|c| c.at <= future.at));
}

#[sqlx::test]
async fn history_requires_current_scope_and_never_returns_other_projects(pool: PgPool) {
    fixture(&pool).await;
    let user = seed::primary_user_id();
    let ws = seed::id(seed::TEAM_WORKSPACE_SLUG);
    let project = seed::id("p_atlas");
    assert!(matches!(
        read_plan(&pool, user, seed::id("w_personal_u_maya"), project, None).await,
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        read_plan(&pool, user, ws, Uuid::new_v4(), None).await,
        Err(ApiError::Forbidden)
    ));
    let history = read_plan(&pool, user, ws, project, None).await.unwrap();
    assert!(history.state.tasks.iter().all(|t| t.project_id == project));
    assert!(history
        .state
        .sprints
        .iter()
        .all(|s| s.project_id == project));
    sqlx::query(
        "UPDATE workspace_members SET removed_at = now() WHERE workspace_id = $1 AND user_id = $2",
    )
    .bind(ws)
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE project_members SET removed_at = now() WHERE user_id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        read_plan(&pool, user, ws, project, None).await,
        Err(ApiError::Forbidden)
    ));
}

#[sqlx::test]
async fn outgoing_move_is_removed_from_source_history_and_available_to_destination(pool: PgPool) {
    fixture(&pool).await;
    let user = seed::primary_user_id();
    let ws = seed::id(seed::TEAM_WORKSPACE_SLUG);
    let from = seed::id("p_atlas");
    let to: Uuid =
        sqlx::query_scalar("SELECT id FROM projects WHERE workspace_id = $1 AND id <> $2 LIMIT 1")
            .bind(ws)
            .bind(from)
            .fetch_one(&pool)
            .await
            .unwrap();
    let task = seed::id("t_atlas_dropped");
    let payload = serde_json::json!({"kind":"task.move_project", "from_project_id":from, "to_project_id":to,
        "task":{"id":task,"project_id":to,"title":"Moved work","section":"later","status":"todo","sort_key":"00009000~"}});
    for project in [from, to] {
        sqlx::query("INSERT INTO processed_ops (op_id,user_id,workspace_id,project_id,kind,payload) VALUES ($1,$2,$3,$4,'task.move_project',$5)")
            .bind(Uuid::new_v4().to_string()).bind(user).bind(ws).bind(project).bind(&payload).execute(&pool).await.unwrap();
    }
    let source = read_plan(&pool, user, ws, from, None).await.unwrap();
    assert!(!source.state.tasks.iter().any(|t| t.id == task));
    let target = read_plan(&pool, user, ws, to, None).await.unwrap();
    let moved = target.state.tasks.iter().find(|t| t.id == task).unwrap();
    assert_eq!(moved.sort_key, "00009000~");
    assert_eq!(moved.sprint_id, None);
}

#[sqlx::test]
async fn exact_revision_distinguishes_changes_with_the_same_timestamp(pool: PgPool) {
    fixture(&pool).await;
    let user = seed::primary_user_id();
    let ws = seed::id(seed::TEAM_WORKSPACE_SLUG);
    let project = seed::id("p_atlas");
    let task = Uuid::new_v4();
    let at = chrono::DateTime::from_timestamp_micros(
        (Utc::now() - Duration::seconds(2)).timestamp_micros(),
    )
    .unwrap();
    let payloads = [
        serde_json::json!({"kind":"task.create","task":{"id":task,"project_id":project,"title":"First revision","section":"later","status":"todo","source":"local"}}),
        serde_json::json!({"kind":"task.set_title","task_id":task,"title":"Second revision"}),
    ];
    let mut seqs = Vec::new();
    for payload in payloads {
        let seq: i64 = sqlx::query_scalar("INSERT INTO processed_ops (op_id,user_id,workspace_id,project_id,kind,payload,applied_at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING seq")
            .bind(Uuid::new_v4().to_string()).bind(user).bind(ws).bind(project)
            .bind(payload["kind"].as_str().unwrap()).bind(&payload).bind(at).fetch_one(&pool).await.unwrap();
        seqs.push(seq);
    }
    for (seq, title) in [(seqs[0], "First revision"), (seqs[1], "Second revision")] {
        let result =
            fira_api::plan_history::read_revision(&pool, user, ws, project, None, Some(seq))
                .await
                .unwrap();
        assert_eq!(result.revision, Some(seq));
        assert_eq!(result.at, at);
        assert_eq!(
            result
                .state
                .tasks
                .iter()
                .find(|t| t.id == task)
                .unwrap()
                .title,
            title
        );
        assert_eq!(result.changes.iter().filter(|c| c.at == at).count(), 2);
    }
    assert!(matches!(
        fira_api::plan_history::read_revision(&pool, user, ws, project, None, Some(i64::MAX)).await,
        Err(ApiError::BadRequest(_))
    ));
}

#[sqlx::test]
async fn historical_unplanned_dates_come_from_logged_completion(pool: PgPool) {
    fixture(&pool).await;
    let user = seed::primary_user_id();
    let ws = seed::id(seed::TEAM_WORKSPACE_SLUG);
    let project = seed::id("p_atlas");
    let task_id = seed::id("t_atlas_loose4");
    let (create_seq, created_at): (i64, chrono::DateTime<Utc>) = sqlx::query_as(
        "SELECT seq, applied_at FROM processed_ops WHERE project_id = $1 AND kind = 'task.create' AND payload->'task'->>'id' = $2"
    ).bind(project).bind(task_id.to_string()).fetch_one(&pool).await.unwrap();
    let (finish_seq, finished_at): (i64, chrono::DateTime<Utc>) = sqlx::query_as(
        "SELECT seq, applied_at FROM processed_ops WHERE project_id = $1 AND kind = 'task.tick' AND payload->>'task_id' = $2 ORDER BY seq LIMIT 1"
    ).bind(project).bind(task_id.to_string()).fetch_one(&pool).await.unwrap();
    let before =
        fira_api::plan_history::read_revision(&pool, user, ws, project, None, Some(create_seq))
            .await
            .unwrap();
    let task = before
        .state
        .tasks
        .iter()
        .find(|task| task.id == task_id)
        .unwrap();
    assert_eq!(task.created_at, Some(created_at));
    assert_eq!(task.finished_at, None);
    // This fixture is imported as done; until its completion op it uses
    // the recorded creation date as the Unplanned fallback.
    assert_eq!(task.status, "done");
    let after =
        fira_api::plan_history::read_revision(&pool, user, ws, project, None, Some(finish_seq))
            .await
            .unwrap();
    let task = after
        .state
        .tasks
        .iter()
        .find(|task| task.id == task_id)
        .unwrap();
    assert_eq!(task.finished_at, Some(finished_at));
    assert_eq!(task.sprint_id, None);
    assert_eq!(task.status, "done");
    // Seeder-only SQL adjustments to the current finish date must not
    // override the completion time recorded in this historical revision.
    let serialized = serde_json::to_value(&after.state.tasks).unwrap();
    let json = serialized
        .as_array()
        .unwrap()
        .iter()
        .find(|task| task["id"] == task_id.to_string())
        .unwrap();
    assert!(json["created_at"].is_string());
    assert!(json["finished_at"].is_string());
}
