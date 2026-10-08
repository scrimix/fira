// Point-in-time projection of a project's plan from its op log.
//
// `processed_ops` stores every op verbatim with `applied_at` and is never
// pruned (0010 dropped its FKs precisely to make it a durable audit
// log), so "what did this board look like in W38" is answerable by
// folding the log up to a timestamp. That fold is this module.
//
// Pure and DB-free on purpose: it takes a slice and returns a struct, so
// it is the one piece of the plan view that `cargo test` can cover
// without infrastructure. The /api/plan/at handler that feeds it rows is
// sprint 32.
//
// Projection lives here rather than in TypeScript because the client
// does not have the op log — it has current state plus a cursor — so
// scrubbing needs a server call regardless. *Assembly* (lane packing,
// badge codes, week indices) stays in web/src/plan.ts, with one
// implementation serving both live and replay.

use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;

use crate::ops::Op;

/// Op kinds that can move the plan board. `block.*` dominates write
/// volume and is irrelevant here, so the whitelist is most of what keeps
/// the query tractable.
pub const PLAN_KINDS: &[&str] = &[
    "task.create",
    "task.delete",
    "task.set_sprint",
    "task.tick",
    "task.set_status",
    "task.set_section",
    "task.set_title",
    "task.move_project",
    "track.create",
    "track.set_title",
    "track.set_color",
    "track.reorder",
    "track.delete",
    "sprint.create",
    "sprint.set_title",
    "sprint.set_dates",
    "sprint.set_track",
    "sprint.delete",
];

/// One row of the log, as the /changes query already shapes it.
#[derive(Debug, Clone)]
pub struct LoggedOp {
    /// Authoritative for order. `applied_at` is not unique.
    pub seq: i64,
    pub applied_at: DateTime<Utc>,
    pub kind: String,
    pub payload: serde_json::Value,
}

/// Field-for-field what `buildPlanSnapshot` reads off a track. Narrower
/// than `models::Track` so the fold never has to fabricate a value it
/// cannot know; TypeScript is structural, so live mode passes the full
/// bootstrap entity into the same assembly function.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlanTrack {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub color: String,
    pub sort_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlanSprint {
    pub id: Uuid,
    pub project_id: Uuid,
    pub track_id: Option<Uuid>,
    pub title: String,
    pub starts_on: Option<NaiveDate>,
    pub ends_on: Option<NaiveDate>,
    pub sort_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlanTask {
    pub id: Uuid,
    pub project_id: Uuid,
    pub track_id: Option<Uuid>,
    pub sprint_id: Option<Uuid>,
    pub title: String,
    pub section: String,
    pub status: String,
    pub sort_key: String,
}

#[derive(Debug, Default, PartialEq, Serialize)]
pub struct PlanState {
    pub tracks: Vec<PlanTrack>,
    pub sprints: Vec<PlanSprint>,
    pub tasks: Vec<PlanTask>,
}

/// Fold `ops` into the plan as it stood at `at`.
///
/// Pure. No DB, no IO — the whole point.
///
/// Ops after `at` are ignored, and an unrecognised kind is skipped
/// rather than fatal: after any rolling deploy this code is older than
/// some of the rows it replays, and a board that refuses to render is
/// worse than one missing a field it has never heard of.
pub fn project_at(ops: &[LoggedOp], at: DateTime<Utc>) -> PlanState {
    let mut f = Fold::default();
    let mut window: Vec<&LoggedOp> = ops.iter().filter(|o| o.applied_at <= at).collect();
    window.sort_by_key(|o| o.seq);
    for op in window {
        f.apply(op);
    }
    f.finish()
}

/// Insertion-ordered maps, so output order follows the log rather than
/// hash order — the derived badge codes depend on a stable sequence.
#[derive(Default)]
struct Fold {
    tracks: HashMap<Uuid, (i64, PlanTrack)>,
    sprints: HashMap<Uuid, (i64, PlanSprint)>,
    tasks: HashMap<Uuid, (i64, PlanTask)>,
}

impl Fold {
    fn apply(&mut self, logged: &LoggedOp) {
        if !PLAN_KINDS.contains(&logged.kind.as_str()) {
            return;
        }
        // `task.move_project` is a server-synthesized kind and not part
        // of the client `Op` union, so it parses on its own.
        if logged.kind == "task.move_project" {
            if let Some(task) = logged.payload.get("task") {
                if let Ok(t) = serde_json::from_value::<MovedTask>(task.clone()) {
                    let entry = self.tasks.entry(t.id).or_insert_with(|| {
                        (
                            logged.seq,
                            PlanTask {
                                id: t.id,
                                project_id: t.project_id,
                                track_id: None,
                                sprint_id: None,
                                title: t.title.clone(),
                                section: t.section.clone(),
                                status: t.status.clone(),
                                sort_key: t.sort_key.clone(),
                            },
                        )
                    });
                    // The move clears both plan links server-side.
                    entry.1.project_id = t.project_id;
                    entry.1.track_id = None;
                    entry.1.sprint_id = None;
                    entry.1.title = t.title;
                    entry.1.section = t.section;
                    entry.1.status = t.status;
                }
            }
            return;
        }
        let Ok(op) = serde_json::from_value::<Op>(logged.payload.clone()) else {
            return;
        };
        let seq = logged.seq;
        match op {
            Op::TaskCreate { task } => {
                self.tasks.insert(
                    task.id,
                    (
                        seq,
                        PlanTask {
                            id: task.id,
                            project_id: task.project_id,
                            track_id: task.track_id,
                            sprint_id: task.sprint_id,
                            title: task.title,
                            section: task.section,
                            status: task.status,
                            sort_key: task.sort_key,
                        },
                    ),
                );
            }
            Op::TaskDelete { task_id } => {
                self.tasks.remove(&task_id);
            }
            Op::TaskSetSprint {
                task_id,
                sprint_id,
            } => {
                if let Some((_, t)) = self.tasks.get_mut(&task_id) {
                    t.sprint_id = sprint_id;
                }
            }
            Op::TaskTick { task_id, done } => {
                if let Some((_, t)) = self.tasks.get_mut(&task_id) {
                    t.status = if done { "done" } else { "in_progress" }.into();
                }
            }
            Op::TaskSetStatus { task_id, status } => {
                if let Some((_, t)) = self.tasks.get_mut(&task_id) {
                    t.status = status;
                }
            }
            Op::TaskSetSection { task_id, section } => {
                if let Some((_, t)) = self.tasks.get_mut(&task_id) {
                    t.section = section;
                }
            }
            Op::TaskSetTitle { task_id, title } => {
                if let Some((_, t)) = self.tasks.get_mut(&task_id) {
                    t.title = title;
                }
            }
            Op::TrackCreate { track } => {
                self.tracks.insert(
                    track.id,
                    (
                        seq,
                        PlanTrack {
                            id: track.id,
                            project_id: track.project_id,
                            title: track.title,
                            color: track.color,
                            sort_key: track.sort_key,
                        },
                    ),
                );
            }
            Op::TrackSetTitle { track_id, title } => {
                if let Some((_, t)) = self.tracks.get_mut(&track_id) {
                    t.title = title;
                }
            }
            Op::TrackSetColor { track_id, color } => {
                if let Some((_, t)) = self.tracks.get_mut(&track_id) {
                    t.color = color;
                }
            }
            Op::TrackReorder { ordered, .. } => {
                for (i, track_id) in ordered.iter().enumerate() {
                    if let Some((_, t)) = self.tracks.get_mut(track_id) {
                        t.sort_key = format!("M{i:03}");
                    }
                }
            }
            Op::TrackDelete { track_id } => {
                self.tracks.remove(&track_id);
                // Mirror ON DELETE SET NULL: children are orphaned, not
                // destroyed. A board that dropped them would read as
                // data loss at every T after the delete.
                for (_, s) in self.sprints.values_mut() {
                    if s.track_id == Some(track_id) {
                        s.track_id = None;
                    }
                }
                for (_, t) in self.tasks.values_mut() {
                    if t.track_id == Some(track_id) {
                        t.track_id = None;
                    }
                }
            }
            Op::SprintCreate { sprint } => {
                self.sprints.insert(
                    sprint.id,
                    (
                        seq,
                        PlanSprint {
                            id: sprint.id,
                            project_id: sprint.project_id,
                            track_id: sprint.track_id,
                            title: sprint.title,
                            starts_on: sprint.starts_on,
                            ends_on: sprint.ends_on,
                            sort_key: sprint.sort_key,
                        },
                    ),
                );
            }
            Op::SprintSetTitle { sprint_id, title } => {
                if let Some((_, s)) = self.sprints.get_mut(&sprint_id) {
                    s.title = title;
                }
            }
            Op::SprintSetDates {
                sprint_id,
                starts_on,
                ends_on,
            } => {
                if let Some((_, s)) = self.sprints.get_mut(&sprint_id) {
                    s.starts_on = Some(starts_on);
                    s.ends_on = Some(ends_on);
                }
            }
            Op::SprintSetTrack {
                sprint_id,
                track_id,
            } => {
                if let Some((_, s)) = self.sprints.get_mut(&sprint_id) {
                    s.track_id = track_id;
                }
            }
            Op::SprintDelete { sprint_id } => {
                self.sprints.remove(&sprint_id);
                for (_, t) in self.tasks.values_mut() {
                    if t.sprint_id == Some(sprint_id) {
                        t.sprint_id = None;
                    }
                }
            }
            _ => {}
        }
    }

    fn finish(self) -> PlanState {
        fn drain<T>(m: HashMap<Uuid, (i64, T)>) -> Vec<T> {
            let mut v: Vec<(i64, T)> = m.into_values().collect();
            v.sort_by_key(|(seq, _)| *seq);
            v.into_iter().map(|(_, x)| x).collect()
        }
        PlanState {
            tracks: drain(self.tracks),
            sprints: drain(self.sprints),
            tasks: drain(self.tasks),
        }
    }
}

/// The subset of `task.move_project`'s embedded task we project.
#[derive(serde::Deserialize)]
struct MovedTask {
    id: Uuid,
    project_id: Uuid,
    title: String,
    section: String,
    status: String,
    #[serde(default = "m")]
    sort_key: String,
}

fn m() -> String {
    "M".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn t(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, day, 12, 0, 0).unwrap()
    }

    fn uid(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    const PROJ: u8 = 1;

    /// `(seq, day, payload)` — seq is implicit in position.
    fn log(rows: &[(u32, serde_json::Value)]) -> Vec<LoggedOp> {
        rows.iter()
            .enumerate()
            .map(|(i, (day, payload))| LoggedOp {
                seq: i as i64 + 1,
                applied_at: t(*day),
                kind: payload["kind"].as_str().unwrap().to_string(),
                payload: payload.clone(),
            })
            .collect()
    }

    fn task_create(task_id: u8, sprint: Option<u8>, title: &str) -> serde_json::Value {
        json!({
            "kind": "task.create",
            "task": {
                "id": uid(task_id),
                "project_id": uid(PROJ),
                "sprint_id": sprint.map(uid),
                "title": title,
                "section": "later",
                "status": "todo",
                "source": "local",
            }
        })
    }

    fn sprint_create(sprint_id: u8, track: Option<u8>, from: &str, to: &str) -> serde_json::Value {
        json!({
            "kind": "sprint.create",
            "sprint": {
                "id": uid(sprint_id),
                "project_id": uid(PROJ),
                "track_id": track.map(uid),
                "title": "A1",
                "starts_on": from,
                "ends_on": to,
            }
        })
    }

    fn track_create(track_id: u8) -> serde_json::Value {
        json!({
            "kind": "track.create",
            "track": { "id": uid(track_id), "project_id": uid(PROJ), "title": "Arch" }
        })
    }

    fn date(s: &str) -> NaiveDate {
        s.parse().unwrap()
    }

    #[test]
    fn empty_log_is_empty_state() {
        assert_eq!(project_at(&[], t(1)), PlanState::default());
    }

    #[test]
    fn a_sprint_moved_twice_reads_its_span_at_each_point() {
        let ops = log(&[
            (1, sprint_create(10, None, "2026-09-07", "2026-09-21")),
            (
                8,
                json!({"kind":"sprint.set_dates","sprint_id":uid(10),
                       "starts_on":"2026-09-14","ends_on":"2026-09-28"}),
            ),
            (
                15,
                json!({"kind":"sprint.set_dates","sprint_id":uid(10),
                       "starts_on":"2026-09-21","ends_on":"2026-10-05"}),
            ),
        ]);
        let span = |day| {
            let s = project_at(&ops, t(day));
            (s.sprints[0].starts_on.unwrap(), s.sprints[0].ends_on.unwrap())
        };
        assert_eq!(span(2), (date("2026-09-07"), date("2026-09-21")));
        assert_eq!(span(9), (date("2026-09-14"), date("2026-09-28")));
        assert_eq!(span(20), (date("2026-09-21"), date("2026-10-05")));
    }

    #[test]
    fn a_task_created_after_t_is_absent_at_t() {
        let ops = log(&[(10, task_create(20, None, "Later"))]);
        assert!(project_at(&ops, t(5)).tasks.is_empty());
        assert_eq!(project_at(&ops, t(11)).tasks.len(), 1);
    }

    #[test]
    fn a_task_deleted_after_t_is_still_present_at_t_with_its_title() {
        let ops = log(&[
            (1, sprint_create(10, None, "2026-09-07", "2026-09-21")),
            (2, task_create(20, Some(10), "Retire the v1 pipeline")),
            (9, json!({"kind":"task.delete","task_id":uid(20)})),
        ]);
        let before = project_at(&ops, t(5));
        assert_eq!(before.tasks.len(), 1);
        assert_eq!(before.tasks[0].title, "Retire the v1 pipeline");
        assert_eq!(before.tasks[0].sprint_id, Some(uid(10)));
        assert!(project_at(&ops, t(10)).tasks.is_empty());
    }

    #[test]
    fn a_task_created_and_deleted_before_t_is_absent() {
        // The deferred case. It must at least not crash.
        let ops = log(&[
            (1, task_create(20, None, "Ghost")),
            (2, json!({"kind":"task.delete","task_id":uid(20)})),
        ]);
        assert!(project_at(&ops, t(9)).tasks.is_empty());
    }

    #[test]
    fn membership_follows_the_last_set_sprint_at_or_before_t() {
        let ops = log(&[
            (1, sprint_create(10, None, "2026-09-07", "2026-09-21")),
            (1, sprint_create(11, None, "2026-09-21", "2026-10-05")),
            (2, task_create(20, None, "Drifter")),
            (5, json!({"kind":"task.set_sprint","task_id":uid(20),"sprint_id":uid(10)})),
            (10, json!({"kind":"task.set_sprint","task_id":uid(20),"sprint_id":uid(11)})),
            (15, json!({"kind":"task.set_sprint","task_id":uid(20),"sprint_id":null})),
        ]);
        let at = |day| project_at(&ops, t(day)).tasks[0].sprint_id;
        assert_eq!(at(3), None);
        assert_eq!(at(6), Some(uid(10)));
        assert_eq!(at(11), Some(uid(11)));
        assert_eq!(at(16), None);
    }

    #[test]
    fn a_retracked_card_sits_on_its_old_track_at_t() {
        let ops = log(&[
            (1, track_create(30)),
            (1, track_create(31)),
            (2, sprint_create(10, Some(30), "2026-09-07", "2026-09-21")),
            (9, json!({"kind":"sprint.set_track","sprint_id":uid(10),"track_id":uid(31)})),
        ]);
        assert_eq!(project_at(&ops, t(5)).sprints[0].track_id, Some(uid(30)));
        assert_eq!(project_at(&ops, t(10)).sprints[0].track_id, Some(uid(31)));
    }

    #[test]
    fn deleting_a_track_orphans_its_children_rather_than_vanishing_them() {
        let ops = log(&[
            (1, track_create(30)),
            (2, sprint_create(10, Some(30), "2026-09-07", "2026-09-21")),
            (3, task_create(20, Some(10), "Member")),
            (9, json!({"kind":"track.delete","track_id":uid(30)})),
        ]);
        let before = project_at(&ops, t(5));
        assert_eq!(before.tracks.len(), 1);
        assert_eq!(before.sprints[0].track_id, Some(uid(30)));

        let after = project_at(&ops, t(10));
        assert!(after.tracks.is_empty());
        assert_eq!(after.sprints.len(), 1, "the sprint survives, orphaned");
        assert_eq!(after.sprints[0].track_id, None);
        assert_eq!(after.tasks.len(), 1, "no task is destroyed");
    }

    #[test]
    fn deleting_a_sprint_returns_its_tasks_to_the_inbox() {
        let ops = log(&[
            (1, sprint_create(10, None, "2026-09-07", "2026-09-21")),
            (2, task_create(20, Some(10), "Member")),
            (9, json!({"kind":"sprint.delete","sprint_id":uid(10)})),
        ]);
        let after = project_at(&ops, t(10));
        assert!(after.sprints.is_empty());
        assert_eq!(after.tasks.len(), 1);
        assert_eq!(after.tasks[0].sprint_id, None);
    }

    #[test]
    fn applied_at_ties_resolve_by_seq() {
        // Both on day 1. The later `seq` must win, in both input orders.
        let a = json!({"kind":"sprint.set_dates","sprint_id":uid(10),
                       "starts_on":"2026-09-14","ends_on":"2026-09-28"});
        let b = json!({"kind":"sprint.set_dates","sprint_id":uid(10),
                       "starts_on":"2026-09-21","ends_on":"2026-10-05"});
        let ops = log(&[
            (1, sprint_create(10, None, "2026-09-07", "2026-09-21")),
            (1, a),
            (1, b),
        ]);
        assert_eq!(
            project_at(&ops, t(1)).sprints[0].starts_on,
            Some(date("2026-09-21"))
        );
        let mut shuffled = ops.clone();
        shuffled.reverse();
        assert_eq!(
            project_at(&shuffled, t(1)).sprints[0].starts_on,
            Some(date("2026-09-21")),
            "order is taken from seq, not from the slice"
        );
    }

    #[test]
    fn an_unknown_kind_is_skipped_not_fatal() {
        let ops = log(&[
            (1, task_create(20, None, "Real")),
            (2, json!({"kind":"sprint.set_vibe","sprint_id":uid(10),"vibe":"ominous"})),
            (3, json!({"kind":"task.set_title","task_id":uid(20),"title":"Renamed"})),
        ]);
        let s = project_at(&ops, t(9));
        assert_eq!(s.tasks.len(), 1);
        assert_eq!(s.tasks[0].title, "Renamed", "the fold continued past it");
    }

    #[test]
    fn a_malformed_payload_for_a_known_kind_is_skipped_not_fatal() {
        let ops = log(&[
            (1, task_create(20, None, "Real")),
            (2, json!({"kind":"sprint.set_dates","sprint_id":"not-a-uuid"})),
            (3, json!({"kind":"task.set_title","task_id":uid(20),"title":"Renamed"})),
        ]);
        assert_eq!(project_at(&ops, t(9)).tasks[0].title, "Renamed");
    }

    #[test]
    fn a_pre_rename_task_create_still_resolves_its_track() {
        // processed_ops is never pruned, so payloads written before 0034
        // still say `epic_id`. The serde alias is what keeps them
        // replayable; without it this task would be trackless.
        let ops = log(&[(
            1,
            json!({
                "kind": "task.create",
                "task": {
                    "id": uid(20), "project_id": uid(PROJ), "epic_id": uid(30),
                    "title": "Legacy", "section": "later", "status": "todo",
                    "source": "local",
                }
            }),
        )]);
        assert_eq!(project_at(&ops, t(9)).tasks[0].track_id, Some(uid(30)));
    }

    #[test]
    fn a_ticked_task_reads_done_at_t_and_open_before_it() {
        let ops = log(&[
            (1, task_create(20, None, "Work")),
            (9, json!({"kind":"task.tick","task_id":uid(20),"done":true})),
        ]);
        assert_eq!(project_at(&ops, t(5)).tasks[0].status, "todo");
        assert_eq!(project_at(&ops, t(10)).tasks[0].status, "done");
    }

    #[test]
    fn track_reorder_rewrites_sort_keys_in_the_given_order() {
        let ops = log(&[
            (1, track_create(30)),
            (1, track_create(31)),
            (
                2,
                json!({"kind":"track.reorder","project_id":uid(PROJ),
                       "ordered":[uid(31), uid(30)]}),
            ),
        ]);
        let s = project_at(&ops, t(9));
        let key = |n: u8| {
            s.tracks
                .iter()
                .find(|t| t.id == uid(n))
                .unwrap()
                .sort_key
                .clone()
        };
        assert_eq!(key(31), "M000");
        assert_eq!(key(30), "M001");
    }

    #[test]
    fn a_moved_task_loses_both_plan_links() {
        let ops = log(&[
            (1, sprint_create(10, None, "2026-09-07", "2026-09-21")),
            (2, task_create(20, Some(10), "Emigrant")),
            (
                9,
                json!({
                    "kind": "task.move_project",
                    "from_project_id": uid(PROJ),
                    "to_project_id": uid(2),
                    "task": {
                        "id": uid(20), "project_id": uid(2), "title": "Emigrant",
                        "section": "later", "status": "todo", "sort_key": "M",
                    },
                    "blocks": [],
                }),
            ),
        ]);
        let before = project_at(&ops, t(5));
        assert_eq!(before.tasks[0].sprint_id, Some(uid(10)));

        let after = project_at(&ops, t(10));
        assert_eq!(after.tasks[0].project_id, uid(2));
        assert_eq!(after.tasks[0].sprint_id, None);
        assert_eq!(after.tasks[0].track_id, None);
    }

    #[test]
    fn an_op_targeting_an_unknown_id_is_a_no_op() {
        // Happens whenever the window starts after an entity was born.
        let ops = log(&[
            (1, json!({"kind":"task.set_sprint","task_id":uid(99),"sprint_id":uid(10)})),
            (1, json!({"kind":"sprint.set_dates","sprint_id":uid(99),
                       "starts_on":"2026-09-07","ends_on":"2026-09-21"})),
            (2, task_create(20, None, "Real")),
        ]);
        let s = project_at(&ops, t(9));
        assert_eq!(s.tasks.len(), 1);
        assert!(s.sprints.is_empty());
    }
}
