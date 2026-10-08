import { useEffect, useRef } from 'react';
import { Select } from './Select';
import type { MoveImpact } from '../moveImpact';
import type { Project, UUID } from '../types';

// Pick a target project for a task, and see what the move costs before
// committing to it.
//
// The picker lives *in* the dialog rather than in the task sidebar for
// two reasons. The impact is what makes the choice, so it should update
// as you try targets — you can compare "moving to Atlas strands Dana"
// against "moving to Orion costs nothing" without closing anything. And
// a <Select> in the sidebar has to coexist with the sidebar's own
// click-away handling, while its menu portals to document.body; that
// combination ate the option click outright.
//
// This dialog is the *only* place any consequence of a move is ever
// visible: tags vanish, the track and sprint clear, and someone's calendar quietly
// empties, with no other notification anywhere in the product. So it is
// exhaustive by design, and it names every item rather than counting
// them — "3 tags will be dropped" makes the user go and look, listing
// them doesn't.
//
// The impact is reported even when nothing is lost ("Nothing will be
// lost"), which is what makes the loud version trustworthy: a warning
// that only ever appears when something is wrong trains people to
// dismiss it unread.
//
// The two sections are separated because they are different kinds of
// worry. Access loss is recoverable — the blocks are never deleted, and
// adding the person to the target project brings them back on the next
// hydrate. The dropped tags/track/sprint are not.

// One person's line in the access-loss list. The assignee flag folds
// into the same sentence rather than becoming a second row, so somebody
// who is both assignee and block owner appears once.
//
// they/them throughout: the store has no pronoun for a user, and
// guessing one from a name would misgender a real person.
function strandedReason(blockCount: number, isAssignee: boolean): string {
  const blocks = blockCount === 1
    ? '1 time block disappears from their calendar'
    : `${blockCount} time blocks disappear from their calendar`;
  const assignee = 'they’re the assignee, so the task stays assigned to someone who can’t open it';
  if (blockCount === 0) return assignee[0].toUpperCase() + assignee.slice(1);
  return isAssignee ? `${blocks}, and ${assignee}` : blocks;
}

interface Props {
  taskTitle: string;
  fromProjectTitle: string;
  /// Candidate targets — the caller's visible projects, current one
  /// already excluded.
  candidates: Project[];
  /// Null until the user picks; the dialog opens with nothing selected
  /// so it can never commit a move the user didn't choose.
  toProject: Project | null;
  onSelectProject: (id: UUID) => void;
  /// Null while no target is selected.
  impact: MoveImpact | null;
  busy?: boolean;
  /// Surfaced in-dialog rather than behind it: a rejected move is
  /// usually a 409 saying the impact list was stale, and the corrected
  /// list is right here for the user to re-read.
  error?: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}

export function MoveTaskModal({
  taskTitle, fromProjectTitle, candidates, toProject, onSelectProject,
  impact, busy, error, onCancel, onConfirm,
}: Props) {
  const confirmRef = useRef<HTMLButtonElement>(null);

  useEffect(() => { confirmRef.current?.focus(); }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      // Let an open <Select> take the first Escape for itself. This
      // listener captures, so without the check it would close the whole
      // dialog out from under a user who only meant to dismiss the
      // dropdown. The menu portals to document.body, so a DOM query is
      // the only handle we have on it.
      if (document.querySelector('.select-menu')) return;
      e.stopPropagation();
      onCancel();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onCancel]);

  // Same backdrop discipline as ConfirmDelete: only dismiss when both
  // the mousedown and the click landed on the backdrop, so a text
  // selection that overshoots the modal doesn't close it.
  const downOnBackdropRef = useRef(false);

  const losesSomething = impact != null
    && (impact.droppedTags.length > 0 || impact.droppedTrack != null || impact.droppedSprint != null);
  const toTitle = toProject?.title ?? '';

  return (
    <div
      className="modal-backdrop confirm-backdrop"
      onMouseDown={(e) => { downOnBackdropRef.current = e.target === e.currentTarget; }}
      onClick={(e) => {
        const onBackdrop = e.target === e.currentTarget;
        if (onBackdrop && downOnBackdropRef.current) onCancel();
        downOnBackdropRef.current = false;
      }}
    >
      <div className="modal confirm-modal move-modal" onClick={(e) => e.stopPropagation()}>
        <div className="confirm-body">
          <h3 className="confirm-title">
            Move “{taskTitle}” out of {fromProjectTitle}
          </h3>

          <div className="move-picker">
            <h5>To project</h5>
            <Select<UUID>
              value={(toProject?.id ?? '') as UUID}
              options={candidates.map((p) => ({ value: p.id, label: p.title }))}
              onChange={onSelectProject}
            />
          </div>

          {impact == null && (
            <div className="confirm-text">
              <p>Pick a project to see what the move affects.</p>
            </div>
          )}

          {impact?.harmless && (
            <div className="confirm-text"><p>Nothing will be lost.</p></div>
          )}

          {impact && impact.stranded.length > 0 && (
            <section className="move-section">
              <h4 className="move-section-title">
                People who can’t see {toTitle}
              </h4>
              <ul className="move-list">
                {impact.stranded.map(({ user, blockCount, isAssignee }) => (
                  <li key={user.id} className="move-list-row">
                    <strong>{user.name}</strong> — {strandedReason(blockCount, isAssignee)}
                  </li>
                ))}
              </ul>
              <p className="move-note">
                Their blocks aren’t deleted. Add them to {toTitle} and
                everything comes back.
              </p>
            </section>
          )}

          {losesSomething && (
            <section className="move-section">
              <h4 className="move-section-title move-section-danger">
                Dropped from the task — permanently
              </h4>
              <ul className="move-list">
                {impact!.droppedTags.length > 0 && (
                  <li className="move-list-row">
                    Tag{impact!.droppedTags.length === 1 ? '' : 's'}{' '}
                    {impact!.droppedTags.map((t, i) => (
                      <span key={t.id}>
                        {i > 0 && ', '}
                        <span className="move-tag" style={{ ['--tag-color' as string]: t.color }}>
                          {t.title}
                        </span>
                      </span>
                    ))}
                  </li>
                )}
                {impact!.droppedTrack && (
                  <li className="move-list-row">Track <strong>{impact!.droppedTrack.title}</strong></li>
                )}
                {impact!.droppedSprint && (
                  <li className="move-list-row">Sprint <strong>{impact!.droppedSprint.title}</strong></li>
                )}
              </ul>
              <p className="move-note">
                Moving the task back to {fromProjectTitle} won’t restore these.
              </p>
            </section>
          )}

          {impact && !impact.harmless && (
            // The two lists above prime the reader to assume everything
            // is at risk; say what survives.
            <p className="move-survives">
              Attachments, subtasks and time blocks move with the task.
            </p>
          )}
          {error && <p className="move-error">{error}</p>}
        </div>
        <div className="modal-footer">
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button
            ref={confirmRef}
            className="btn move-confirm"
            onClick={onConfirm}
            disabled={busy || toProject == null}
            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); onConfirm(); } }}
          >
            {busy ? 'Moving…' : toProject ? `Move to ${toTitle}` : 'Move'}
          </button>
        </div>
      </div>
    </div>
  );
}
