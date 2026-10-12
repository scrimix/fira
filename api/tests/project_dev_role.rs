use axum::{extract::State, Json};
use fira_api::{
    auth::{AuthConfig, AuthCtx, AuthUser},
    db, load_bootstrap,
    ops::{self, OpEnvelope, OpsRequest},
    pubsub::Hub,
    storage::{LocalStorage, StorageBackend},
    AppState,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const OWNER: Uuid = Uuid::from_u128(1);
const DEV: Uuid = Uuid::from_u128(2);
const WS: Uuid = Uuid::from_u128(3);
const PRIVATE: Uuid = Uuid::from_u128(4);
const NORMAL: Uuid = Uuid::from_u128(5);
const TASK: Uuid = Uuid::from_u128(6);
const OTHER_TASK: Uuid = Uuid::from_u128(7);
const OWN_BLOCK: Uuid = Uuid::from_u128(8);
const TEAM_BLOCK: Uuid = Uuid::from_u128(9);
const NORMAL_BLOCK: Uuid = Uuid::from_u128(10);

async fn seed(pool: &PgPool) {
    for (id, name) in [(OWNER, "Owner"), (DEV, "Developer")] {
        sqlx::query("INSERT INTO users (id,email,name,initials) VALUES ($1,$2,$3,'XX')")
            .bind(id)
            .bind(format!("{name}@test.dev"))
            .bind(name)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query(
        "INSERT INTO workspaces (id,title,is_personal,created_by) VALUES ($1,'Team',false,$2)",
    )
    .bind(WS)
    .bind(OWNER)
    .execute(pool)
    .await
    .unwrap();
    for (id, role) in [(OWNER, "owner"), (DEV, "member")] {
        sqlx::query("INSERT INTO workspace_members (workspace_id,user_id,role) VALUES ($1,$2,$3)")
            .bind(WS)
            .bind(id)
            .bind(role)
            .execute(pool)
            .await
            .unwrap();
    }
    for (project, task, role) in [(PRIVATE, TASK, "dev"), (NORMAL, OTHER_TASK, "member")] {
        sqlx::query("INSERT INTO projects (id,workspace_id,title,color,source,owner_id) VALUES ($1,$2,'Project','#123456','local',$3)")
            .bind(project).bind(WS).bind(OWNER).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO project_members (project_id,user_id,role) VALUES ($1,$2,$3)")
            .bind(project)
            .bind(DEV)
            .bind(role)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO tasks (id,project_id,title,section,status,source) VALUES ($1,$2,'Task','later','todo','local')")
            .bind(task).bind(project).execute(pool).await.unwrap();
    }
    for (block, task, user) in [
        (OWN_BLOCK, TASK, DEV),
        (TEAM_BLOCK, TASK, OWNER),
        (NORMAL_BLOCK, OTHER_TASK, OWNER),
    ] {
        sqlx::query("INSERT INTO time_blocks (id,task_id,user_id,start_at,end_at,state) VALUES ($1,$2,$3,'2026-10-12 08:00Z','2026-10-12 09:00Z','planned')")
            .bind(block).bind(task).bind(user).execute(pool).await.unwrap();
    }
}

fn app(pool: &PgPool) -> AppState {
    AppState {
        pool: pool.clone(),
        hub: Hub::new(),
        build_id: "test".into(),
        storage: StorageBackend::Local(LocalStorage::new("/tmp/fira-dev-role-test".into())),
        auth: AuthConfig {
            google_client_id: String::new(),
            google_client_secret: String::new(),
            redirect_url: String::new(),
            app_base_url: String::new(),
            cookie_secure: false,
            dev_auth: false,
        },
    }
}

async fn send(pool: &PgPool, user: Uuid, payload: Value) -> ops::OpResult {
    let ctx = AuthCtx {
        workspace_id: WS,
        role: if user == OWNER { "owner" } else { "member" }.into(),
        user: AuthUser {
            id: user,
            email: "test@test.dev".into(),
            name: "Test".into(),
            initials: "TE".into(),
            avatar_url: None,
        },
    };
    let (_, Json(response)) = ops::post_ops(
        State(app(pool)),
        ctx,
        Json(OpsRequest {
            ops: vec![OpEnvelope {
                op_id: Uuid::new_v4().to_string(),
                payload,
            }],
        }),
    )
    .await
    .unwrap();
    response.results.into_iter().next().unwrap()
}

#[sqlx::test]
async fn bootstrap_and_linked_calendar_respect_project_role(pool: PgPool) {
    seed(&pool).await;
    let data = load_bootstrap(&pool, WS, DEV).await.unwrap();
    assert_eq!(data.projects.len(), 2);
    assert_eq!(data.tasks.len(), 2);
    let ids: Vec<_> = data.blocks.iter().map(|b| b.id).collect();
    assert!(ids.contains(&OWN_BLOCK));
    assert!(ids.contains(&NORMAL_BLOCK));
    assert!(!ids.contains(&TEAM_BLOCK));
    assert_eq!(
        load_bootstrap(&pool, WS, OWNER).await.unwrap().blocks.len(),
        3
    );
    let partner = db::list_blocks_for_user(&pool, OWNER, DEV).await.unwrap();
    assert_eq!(partner.len(), 1);
    assert_eq!(partner[0].id, NORMAL_BLOCK);
    assert_eq!(
        db::list_linked_tasks_for_blocks(&pool, OWNER, DEV)
            .await
            .unwrap()
            .len(),
        1
    );
    sqlx::query("UPDATE project_members SET role='member' WHERE project_id=$1 AND user_id=$2")
        .bind(PRIVATE)
        .bind(DEV)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        load_bootstrap(&pool, WS, DEV).await.unwrap().blocks.len(),
        3
    );
}

#[sqlx::test]
async fn dev_can_edit_plans_tasks_and_own_blocks_but_not_teammate_blocks(pool: PgPool) {
    seed(&pool).await;
    assert_eq!(
        send(
            &pool,
            DEV,
            json!({"kind":"task.set_title","task_id":TASK,"title":"Updated"})
        )
        .await
        .status,
        "ok"
    );
    let track = Uuid::new_v4();
    assert_eq!(send(&pool, DEV, json!({"kind":"track.create","track":{"id":track,"project_id":PRIVATE,"title":"Track","color":"#123456","sort_key":"M"}})).await.status, "ok");
    let sprint = Uuid::new_v4();
    assert_eq!(send(&pool, DEV, json!({"kind":"sprint.create","sprint":{"id":sprint,"project_id":PRIVATE,"track_id":track,"title":"Sprint","starts_on":"2026-10-12","ends_on":"2026-10-19","sort_key":"M"}})).await.status, "ok");
    assert_eq!(
        send(
            &pool,
            DEV,
            json!({"kind":"task.set_sprint","task_id":TASK,"sprint_id":sprint})
        )
        .await
        .status,
        "ok"
    );
    assert_eq!(
        send(
            &pool,
            DEV,
            json!({"kind":"block.update","block_id":OWN_BLOCK,"patch":{"state":"completed"}})
        )
        .await
        .status,
        "ok"
    );
    assert_eq!(
        send(
            &pool,
            DEV,
            json!({"kind":"block.update","block_id":TEAM_BLOCK,"patch":{"state":"completed"}})
        )
        .await
        .status,
        "error"
    );
    assert_eq!(
        send(
            &pool,
            DEV,
            json!({"kind":"block.delete","block_id":TEAM_BLOCK})
        )
        .await
        .status,
        "error"
    );
    let block = json!({"id":Uuid::new_v4(),"task_id":TASK,"user_id":OWNER,"start_at":"2026-10-12T08:00:00Z","end_at":"2026-10-12T09:00:00Z","state":"planned"});
    assert_eq!(
        send(&pool, DEV, json!({"kind":"block.create","block":block}))
            .await
            .status,
        "error"
    );
    let mut own = block.clone();
    own["user_id"] = json!(DEV);
    assert_eq!(
        send(&pool, DEV, json!({"kind":"block.create","block":own}))
            .await
            .status,
        "ok"
    );
    // Ordinary project permissions remain unchanged.
    assert_eq!(
        send(
            &pool,
            DEV,
            json!({"kind":"block.update","block_id":NORMAL_BLOCK,"patch":{"state":"completed"}})
        )
        .await
        .status,
        "ok"
    );
    let mut tx = pool.begin().await.unwrap();
    let project = db::set_project_members_tx(&mut tx, PRIVATE, &[(DEV, "lead".into())], false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        project
            .members
            .iter()
            .find(|m| m.user_id == DEV)
            .unwrap()
            .role,
        "dev"
    );
    tx.rollback().await.unwrap();
    assert!(!db::has_project_lead_authority(&pool, WS, PRIVATE, DEV)
        .await
        .unwrap());
}

#[sqlx::test]
async fn change_feed_filters_blocks_advances_cursor_and_sanitizes_moves(pool: PgPool) {
    seed(&pool).await;
    // An owner can edit another user's block. Visibility uses block ownership,
    // not the author of the operation, and ignores forged client metadata.
    assert_eq!(send(&pool, OWNER, json!({"kind":"block.update","block_id":OWN_BLOCK,"block_user_id":OWNER,"patch":{"state":"completed"}})).await.status, "ok");
    assert_eq!(
        send(
            &pool,
            OWNER,
            json!({"kind":"block.delete","block_id":OWN_BLOCK})
        )
        .await
        .status,
        "ok"
    );
    assert_eq!(
        send(
            &pool,
            OWNER,
            json!({"kind":"block.delete","block_id":TEAM_BLOCK,"block_user_id":DEV})
        )
        .await
        .status,
        "ok"
    );
    let response = ops::changes_for_user(&pool, WS, DEV, 0).await.unwrap();
    assert_eq!(response.ops.len(), 3);
    assert!(response
        .ops
        .iter()
        .filter(|op| op.kind.starts_with("block."))
        .all(|op| op.payload["block_id"] == json!(OWN_BLOCK)));
    assert!(response
        .ops
        .iter()
        .any(|op| op.kind == "project.time_visibility"));
    assert_eq!(response.cursor, ops::current_cursor(&pool).await.unwrap());
    let previous = response.cursor;
    let mut tx = pool.begin().await.unwrap();
    for _ in 0..501 {
        ops::record_synthesized_op(
            &mut tx,
            OWNER,
            WS,
            "block.create",
            json!({"kind":"block.create","block":{"user_id":OWNER}}),
            Some(PRIVATE),
        )
        .await
        .unwrap();
    }
    ops::record_synthesized_op(
        &mut tx,
        OWNER,
        WS,
        "task.move_project",
        json!({
            "kind":"task.move_project", "from_project_id":NORMAL, "to_project_id":PRIVATE,
            "task":{"id":OTHER_TASK}, "blocks":[{"user_id":OWNER},{"user_id":DEV}]
        }),
        Some(NORMAL),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let hidden_page = ops::changes_for_user(&pool, WS, DEV, previous)
        .await
        .unwrap();
    assert_eq!(hidden_page.ops.len(), 1);
    assert_eq!(hidden_page.ops[0].kind, "project.time_visibility");
    assert!(hidden_page.cursor > previous);
    let moves = ops::changes_for_user(&pool, WS, DEV, hidden_page.cursor)
        .await
        .unwrap();
    assert_eq!(moves.ops.len(), 2);
    let move_entry = moves
        .ops
        .iter()
        .find(|op| op.kind == "task.move_project")
        .unwrap();
    assert_eq!(move_entry.payload["blocks"], json!([{"user_id":DEV}]));
    let all = ops::changes_for_user(&pool, WS, OWNER, hidden_page.cursor)
        .await
        .unwrap();
    assert_eq!(all.ops[1].payload["blocks"].as_array().unwrap().len(), 2);
}

#[sqlx::test]
async fn legacy_updates_and_outgoing_moves_do_not_expose_private_blocks(pool: PgPool) {
    seed(&pool).await;
    // Pre-role logs have no trusted ownership column. An ignored payload
    // field must not override the actual block owner in the fallback path.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO processed_ops (op_id,user_id,workspace_id,project_id,kind,payload) VALUES ($1,$2,$3,$4,'block.update',$5)")
        .bind(Uuid::new_v4().to_string()).bind(OWNER).bind(WS).bind(PRIVATE)
        .bind(json!({"kind":"block.update","block_id":TEAM_BLOCK,"block_user_id":DEV,"block":{"user_id":DEV},"patch":{"state":"completed"}}))
        .execute(&mut *tx).await.unwrap();
    ops::record_synthesized_op(
        &mut tx,
        OWNER,
        WS,
        "task.move_project",
        json!({
            "kind":"task.move_project", "from_project_id":PRIVATE, "to_project_id":Uuid::new_v4(),
            "task":{"id":TASK}, "blocks":[{"user_id":OWNER},{"user_id":DEV}]
        }),
        Some(PRIVATE),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let response = ops::changes_for_user(&pool, WS, DEV, 0).await.unwrap();
    assert_eq!(response.ops.len(), 2);
    assert_eq!(
        response
            .ops
            .iter()
            .find(|op| op.kind == "task.move_project")
            .unwrap()
            .payload["blocks"],
        json!([])
    );
    sqlx::query("UPDATE project_members SET removed_at=now() WHERE project_id=$1 AND user_id=$2")
        .bind(PRIVATE)
        .bind(DEV)
        .execute(&pool)
        .await
        .unwrap();
    // Removed dev members can receive the final project-removal op, but
    // replaying their old cursor must not reveal previously hidden blocks.
    let removed = ops::changes_for_user(&pool, WS, DEV, 0).await.unwrap();
    assert!(removed.ops.iter().all(|op| !op.kind.starts_with("block.")));
}

#[sqlx::test]
async fn seeded_teammate_calendars_support_dev_privacy_testing(pool: PgPool) {
    let mut tx = pool.begin().await.unwrap();
    fira_api::seed::seed_all(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let maya = fira_api::seed::primary_user_id();
    let workspace = fira_api::seed::id(fira_api::seed::TEAM_WORKSPACE_SLUG);
    let atlas = fira_api::seed::id("p_atlas");
    let before = load_bootstrap(&pool, workspace, maya).await.unwrap();
    for teammate in ["u_anna", "u_bob", "u_jin"] {
        assert_eq!(
            before
                .blocks
                .iter()
                .filter(|b| b.user_id == fira_api::seed::id(teammate))
                .count(),
            2
        );
    }
    sqlx::query("UPDATE project_members SET role='dev' WHERE project_id=$1 AND user_id=$2")
        .bind(atlas)
        .bind(maya)
        .execute(&pool)
        .await
        .unwrap();
    let after = load_bootstrap(&pool, workspace, maya).await.unwrap();
    assert!(after
        .blocks
        .iter()
        .all(|b| b.user_id == maya || b.user_id == fira_api::seed::id("u_jin")));
    assert_eq!(
        before.blocks.iter().filter(|b| b.user_id == maya).count(),
        after.blocks.iter().filter(|b| b.user_id == maya).count()
    );
    assert_eq!(before.tasks.len(), after.tasks.len());
    assert_eq!(before.sprints.len(), after.sprints.len());
}

#[sqlx::test]
async fn private_time_flags_reveal_presence_without_block_details(pool: PgPool) {
    seed(&pool).await;
    let bootstrap = load_bootstrap(&pool, WS, DEV).await.unwrap();
    assert!(
        bootstrap
            .tasks
            .iter()
            .find(|t| t.id == TASK)
            .unwrap()
            .has_private_time
    );
    assert!(
        !bootstrap
            .tasks
            .iter()
            .find(|t| t.id == OTHER_TASK)
            .unwrap()
            .has_private_time
    );
    assert!(load_bootstrap(&pool, WS, OWNER)
        .await
        .unwrap()
        .tasks
        .iter()
        .all(|t| !t.has_private_time));
    assert_eq!(
        send(
            &pool,
            OWNER,
            json!({"kind":"block.update","block_id":TEAM_BLOCK,"patch":{"state":"completed"}})
        )
        .await
        .status,
        "ok"
    );
    let presence = ops::changes_for_user(&pool, WS, DEV, 0).await.unwrap();
    assert_eq!(presence.ops.len(), 1);
    assert_eq!(
        presence.ops[0].payload,
        json!({"kind":"project.time_visibility","project_id":PRIVATE,"private_task_ids":[TASK]})
    );
    let cursor = presence.cursor;
    assert_eq!(
        send(
            &pool,
            OWNER,
            json!({"kind":"block.delete","block_id":TEAM_BLOCK})
        )
        .await
        .status,
        "ok"
    );
    let cleared = ops::changes_for_user(&pool, WS, DEV, cursor).await.unwrap();
    assert_eq!(cleared.ops[0].payload["private_task_ids"], json!([]));
    assert!(
        !load_bootstrap(&pool, WS, DEV)
            .await
            .unwrap()
            .tasks
            .iter()
            .find(|t| t.id == TASK)
            .unwrap()
            .has_private_time
    );
}
