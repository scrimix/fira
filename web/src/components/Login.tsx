import { useEffect, useState } from 'react';
import { api, loginUrl } from '../api';

export function Login() {
  // dev_auth gates the "Sign in as Maya" affordance; we only render it
  // when the server has DEV_AUTH=1, so production builds never show it.
  const [devAuth, setDevAuth] = useState(false);
  const [signing, setSigning] = useState(false);
  const [signError, setSignError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .authConfig()
      .then((c) => {
        if (!cancelled) setDevAuth(c.dev_auth);
      })
      .catch(() => {
        // If config fails, treat as prod and hide the button. Login still works.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const onMayaSignIn = async () => {
    if (signing) return;
    setSigning(true);
    setSignError(null);
    try {
      // dev-login drops a session cookie and 302s to "/". We follow with a
      // hard reload either way so /me runs against the fresh cookie and the
      // store hydrates from a clean state.
      const res = await api.devLogin('maya@fira.dev');
      if (!res.ok && res.type !== 'opaqueredirect') {
        throw new Error(`dev-login failed (${res.status})`);
      }
      window.location.assign('/');
    } catch (e) {
      setSignError(e instanceof Error ? e.message : String(e));
      setSigning(false);
    }
  };

  return (
    <div className="login-shell">
      <div className="login-card">
        <div className="login-head">
          <Mark />
          <span className="login-wordmark">Fira</span>
        </div>
        <p className="login-tag">Calendar-first task management.</p>
        <a className="login-google" href={loginUrl}>
          <GoogleMark /> Continue with Google
        </a>
        {devAuth && (
          <>
            <button
              type="button"
              className="login-dev"
              onClick={onMayaSignIn}
              disabled={signing}
            >
              {signing ? 'Signing in…' : 'Sign in as Maya'}
            </button>
            <p className="login-dev-hint">
              Dev mode · uses the fixture user. Reseed with{' '}
              <code>cargo run --bin seed -- --drop</code>.
            </p>
            {signError && <p className="login-dev-error">{signError}</p>}
          </>
        )}
      </div>
    </div>
  );
}

// Three stacked time-block bars; the middle one is the "now" — accent cyan.
// Visualizes a planned day at a glance and reads as Fira's unit of work.
function Mark() {
  return (
    <svg className="login-mark" width="44" height="44" viewBox="0 0 44 44" aria-hidden="true">
      <rect x="2.5" y="2.5" width="39" height="39" fill="none" stroke="currentColor" strokeWidth="1"/>
      <rect x="9" y="10" width="20" height="5" fill="currentColor" opacity="0.85"/>
      <rect x="9" y="19" width="26" height="5" fill="var(--accent)"/>
      <rect x="9" y="28" width="14" height="5" fill="currentColor" opacity="0.45"/>
    </svg>
  );
}

function GoogleMark() {
  return (
    <svg width="16" height="16" viewBox="0 0 18 18" aria-hidden="true">
      <path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62z"/>
      <path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.81.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.71H.96v2.34A8.997 8.997 0 0 0 9 18z"/>
      <path fill="#FBBC05" d="M3.97 10.71A5.41 5.41 0 0 1 3.68 9c0-.6.1-1.18.29-1.71V4.95H.96A8.997 8.997 0 0 0 0 9c0 1.45.35 2.83.96 4.05l3.01-2.34z"/>
      <path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.58C13.46.89 11.43 0 9 0A8.997 8.997 0 0 0 .96 4.95l3.01 2.34C4.68 5.16 6.66 3.58 9 3.58z"/>
    </svg>
  );
}
