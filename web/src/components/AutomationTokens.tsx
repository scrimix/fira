import { useEffect, useState } from 'react';
import { Check, Copy, KeyRound } from 'lucide-react';
import { api, type AutomationToken } from '../api';

// Tokens for non-browser clients (task-cli). Each is pinned to the active
// workspace and works only on the /api/cli routes. The plaintext is shown
// once, right after creation; the server keeps only its hash.
export function AutomationTokens() {
  const [tokens, setTokens] = useState<AutomationToken[] | null>(null);
  const [name, setName] = useState('');
  const [canWrite, setCanWrite] = useState(true);
  const [created, setCreated] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = () => api.listAutomationTokens().then(setTokens).catch((e) => setError(String(e.message ?? e)));
  useEffect(() => { void reload(); }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const t = await api.createAutomationToken(name.trim(), canWrite);
      setCreated(t.token);
      setCopied(false);
      setName('');
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (t: AutomationToken) => {
    if (!window.confirm(`Revoke "${t.name}"? Anything using it stops working immediately.`)) return;
    try {
      await api.revokeAutomationToken(t.id);
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const copy = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="tokens">
      <p className="account-row-text account-row-muted">
        Paste a token into <code>task-cli login fira</code>. It acts as you in this workspace,
        only through the CLI API.
      </p>

      {created && (
        <div className="tokens-new">
          <span className="tokens-new-label">Copy it now — it won't be shown again</span>
          <div className="tokens-new-row">
            <code className="tokens-new-value" onClick={(e) => window.getSelection()?.selectAllChildren(e.currentTarget)}>
              {created}
            </code>
            <button type="button" className="btn" onClick={() => { void copy(); }}>
              {copied ? <Check size={13} strokeWidth={1.75} /> : <Copy size={13} strokeWidth={1.75} />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      {tokens && tokens.length > 0 && (
        <ul className="tokens-list">
          {tokens.map((t) => (
            <li key={t.id} className="tokens-item">
              <span className="tokens-name">{t.name}</span>
              <span className="tokens-meta">
                {t.token_prefix}… · {t.can_write ? 'read & write' : 'read-only'} ·{' '}
                {t.last_used_at ? `used ${new Date(t.last_used_at).toLocaleDateString()}` : 'never used'}
              </span>
              <button type="button" className="tokens-revoke" onClick={() => { void revoke(t); }}>
                Revoke
              </button>
            </li>
          ))}
        </ul>
      )}

      <form className="tokens-form" onSubmit={(e) => { void create(e); }}>
        <input
          className="tokens-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Name, e.g. laptop"
          maxLength={80}
          disabled={busy}
          spellCheck={false}
        />
        <div className="list-tag-filter-mode" role="group" aria-label="Token access">
          <button
            type="button"
            className="list-tag-filter-mode-seg"
            data-active={!canWrite || undefined}
            onClick={() => setCanWrite(false)}
            disabled={busy}
          >
            read-only
          </button>
          <button
            type="button"
            className="list-tag-filter-mode-seg"
            data-active={canWrite || undefined}
            onClick={() => setCanWrite(true)}
            disabled={busy}
          >
            read &amp; write
          </button>
        </div>
        <button type="submit" className="btn" disabled={busy || !name.trim()}>
          <KeyRound size={13} strokeWidth={1.75} /> {busy ? 'Creating…' : 'Create'}
        </button>
      </form>
      {error && <p className="account-row-text account-row-warn">{error}</p>}
    </div>
  );
}
