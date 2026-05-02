import { useEffect, useRef, useState } from 'react';

interface Props {
  title: string;
  body: React.ReactNode;
  // When set, the user must type this exact string to enable Delete.
  // Used for high-blast-radius deletions (project, workspace).
  confirmName?: string;
  // Defaults to "Delete".
  confirmLabel?: string;
  onCancel: () => void;
  onConfirm: () => void;
}

export function ConfirmDelete({
  title, body, confirmName, confirmLabel = 'Delete', onCancel, onConfirm,
}: Props) {
  const [typed, setTyped] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const guarded = confirmName != null;
  const matches = !guarded || typed === confirmName;

  useEffect(() => {
    if (guarded) inputRef.current?.focus();
    else confirmRef.current?.focus();
  }, [guarded]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); onCancel(); }
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onCancel]);

  const tryConfirm = () => { if (matches) onConfirm(); };

  return (
    <div className="modal-backdrop confirm-backdrop" onClick={onCancel}>
      <div className="modal confirm-modal" onClick={(e) => e.stopPropagation()}>
        <div className="confirm-body">
          <h3 className="confirm-title">{title}</h3>
          <div className="confirm-text">{body}</div>
          {guarded && (
            <>
              <label className="confirm-guard-label">
                Type <strong>{confirmName}</strong> to confirm
              </label>
              <input
                ref={inputRef}
                className="confirm-guard-input"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') { e.preventDefault(); tryConfirm(); }
                }}
                spellCheck={false}
                autoComplete="off"
              />
            </>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn" onClick={onCancel}>Cancel</button>
          <button
            ref={confirmRef}
            className="btn confirm-danger"
            disabled={!matches}
            onClick={tryConfirm}
            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); tryConfirm(); } }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
