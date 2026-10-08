use fira_api::{
    db,
    plan_history::{read_history, read_snapshot},
    plan_stress_seed::{self, Config},
    seed,
};
use sqlx::PgPool;

#[sqlx::test]
async fn stress_profiles_are_browseable_consistent_and_repeatable(pool: PgPool) {
    let mut tx = pool.begin().await.unwrap();
    seed::seed_all(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let workspace = seed::id(seed::TEAM_WORKSPACE_SLUG);
    let original_projects = db::project_scope(&pool, seed::primary_user_id(), workspace)
        .await
        .unwrap();
    let original_tasks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
        .fetch_one(&pool)
        .await
        .unwrap();
    let original_logs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM processed_ops")
        .fetch_one(&pool)
        .await
        .unwrap();
    let config = Config {
        revisions: vec![100, 300],
        tasks: 20,
        days: 90,
    };
    plan_stress_seed::seed_profiles(&pool, workspace, &config)
        .await
        .unwrap();
    let owner = seed::primary_user_id();
    for count in config.revisions.iter().copied() {
        let project = plan_stress_seed::project_id(workspace, count);
        let history = read_history(&pool, owner, workspace, project, None)
            .await
            .unwrap();
        assert_eq!(history.changes.len(), count);
        assert_eq!(
            history.changes.last().unwrap().at - history.genesis.unwrap(),
            chrono::Duration::days(90)
        );
        assert!(history
            .changes
            .windows(2)
            .all(|pair| pair[0].at < pair[1].at && pair[0].seq < pair[1].seq));
        assert!(history
            .changes
            .iter()
            .any(|op| op.kind == "sprint.set_dates"));
        let latest = read_snapshot(&pool, owner, workspace, project, None, None)
            .await
            .unwrap();
        let tasks = db::list_tasks_in_scope(&pool, &[project]).await.unwrap();
        assert_eq!(latest.state.tasks.len(), config.tasks);
        assert_eq!(tasks.len(), config.tasks);
        for projected in &latest.state.tasks {
            let live = tasks.iter().find(|t| t.id == projected.id).unwrap();
            assert_eq!(
                (
                    &live.title,
                    &live.section,
                    &live.status,
                    &live.sort_key,
                    live.sprint_id,
                    live.track_id
                ),
                (
                    &projected.title,
                    &projected.section,
                    &projected.status,
                    &projected.sort_key,
                    projected.sprint_id,
                    projected.track_id
                )
            );
            assert_eq!(Some(live.created_at), projected.created_at);
            assert_eq!(live.finished_at, projected.finished_at);
        }
        let tracks = db::list_tracks_in_scope(&pool, &[project]).await.unwrap();
        assert_eq!(tracks.len(), plan_stress_seed::TRACKS);
        for projected in &latest.state.tracks {
            let live = tracks.iter().find(|t| t.id == projected.id).unwrap();
            assert_eq!(
                (&live.title, &live.color, &live.sort_key),
                (&projected.title, &projected.color, &projected.sort_key)
            );
        }
        let sprints = db::list_sprints_in_scope(&pool, &[project]).await.unwrap();
        assert_eq!(sprints.len(), plan_stress_seed::SPRINTS);
        for projected in &latest.state.sprints {
            let live = sprints.iter().find(|t| t.id == projected.id).unwrap();
            assert_eq!(
                (
                    &live.title,
                    &live.sort_key,
                    live.track_id,
                    live.starts_on,
                    live.ends_on
                ),
                (
                    &projected.title,
                    &projected.sort_key,
                    projected.track_id,
                    projected.starts_on,
                    projected.ends_on
                )
            );
        }
        let early = read_snapshot(
            &pool,
            owner,
            workspace,
            project,
            None,
            Some(history.changes[0].seq),
        )
        .await
        .unwrap();
        assert_eq!(early.state.tracks.len(), 1);
        assert!(early.state.tasks.is_empty());
        let authors: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT user_id) FROM processed_ops WHERE project_id=$1",
        )
        .bind(project)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(authors, 4);
    }
    // Replace one profile with another; stale rows/logs must disappear and
    // the personal workspace must remain accessible across a rerun.
    let replaced = Config {
        revisions: vec![150],
        tasks: 25,
        days: 30,
    };
    plan_stress_seed::seed_profiles(&pool, workspace, &replaced)
        .await
        .unwrap();
    plan_stress_seed::seed_profiles(&pool, workspace, &replaced)
        .await
        .unwrap();
    let scope = db::project_scope(&pool, owner, workspace).await.unwrap();
    let new_project = plan_stress_seed::project_id(workspace, 150);
    assert!(scope.contains(&new_project));
    assert_eq!(scope.len(), original_projects.len() + 1);
    for id in &original_projects {
        assert!(scope.contains(id));
    }
    assert_eq!(
        read_history(&pool, owner, workspace, new_project, None)
            .await
            .unwrap()
            .changes
            .len(),
        150
    );
    let logs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM processed_ops WHERE project_id=$1")
        .bind(new_project)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(logs, 150);
    let personal: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workspaces WHERE id=$1)")
        .bind(seed::id("w_personal_u_maya"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(personal);
    let total_tasks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
        .fetch_one(&pool)
        .await
        .unwrap();
    let total_logs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM processed_ops")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total_tasks, original_tasks + replaced.tasks as i64);
    assert_eq!(total_logs, original_logs + 150);
}

#[test]
fn invalid_profiles_are_rejected_before_any_writes() {
    for config in [
        Config {
            revisions: vec![10],
            tasks: 20,
            days: 90,
        },
        Config {
            revisions: vec![100, 100],
            tasks: 20,
            days: 90,
        },
        Config {
            revisions: vec![100],
            tasks: 0,
            days: 90,
        },
        Config {
            revisions: vec![100],
            tasks: 20,
            days: 0,
        },
        Config {
            revisions: vec![],
            tasks: 20,
            days: 90,
        },
    ] {
        assert!(config.validate().is_err());
    }
    assert!(Config::default().validate().is_ok());
}
