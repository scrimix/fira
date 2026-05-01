import { useEffect, useState } from 'react';
import { api, loginUrl } from '../api';
import { useFira } from '../store';
import { BrandMark } from './BrandMark';

const SUBTITLES = [
  'Make plans real.',
  'Looks familiar. Works differently.',
  'Stop handling everything in your head, write things down.',
  'Idea? Capture. Bug? Log. Think later.',
  'Plan together. Adjust together.',
  'Plan what actually fits.',
  'Plans drift. Adjust.',
  'Built for how work actually happens.',
  "'I'll do it tomorrow.' — tomorrow.",
  'A task in-progress for weeks is a signal.',
  'Your plan needs feedback from reality.',
  "Meetings aren't the only thing that takes time.",
  'Stop scheduling "deep work." Schedule the work.',
  'The last 20% is another 80%.',
  'Scope hides until the deadline shows up.',
];

export function Login() {
  // dev_auth gates the "Sign in as Maya" affordance; we only render it
  // when the server has DEV_AUTH=1, so production builds never show it.
  const [devAuth, setDevAuth] = useState(false);
  const [signing, setSigning] = useState(false);
  const [signError, setSignError] = useState<string | null>(null);
  const [subtitle] = useState(
    () => SUBTITLES[Math.floor(Math.random() * SUBTITLES.length)],
  );
  const enterPlayground = useFira((s) => s.enterPlayground);

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
          <BrandMark size={44} className="login-mark" />
          <span className="login-wordmark">Fira</span>
        </div>
        <p className="login-tag">{subtitle}</p>
        <a className="login-google" href={loginUrl}>
          <GoogleMark /> Continue with Google
        </a>
        <button
          type="button"
          className="login-playground"
          onClick={() => enterPlayground()}
          title="Try Fira as Maya Chen — fully in your browser, no account needed"
        >
          Try as Maya in your browser
        </button>
        <p className="login-playground-hint">
          Playground mode · changes stay on this device, no account.
        </p>
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
