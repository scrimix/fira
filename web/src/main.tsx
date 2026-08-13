import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

// Self-hosted webfonts, replacing the Google Fonts <link> that used to live in
// index.html. That link broke: Google rotates the woff2 filenames behind a
// given font version, and any browser holding a cached copy of the stylesheet
// keeps requesting files that no longer exist (404s in the console, text
// falling back to a system font until the CSS cache expires).
//
// Serving them ourselves also drops two external preconnects from the critical
// path, keeps visitor IPs from reaching Google, and lets the fonts inherit the
// `immutable` caching the api applies to hashed assets.
//
// These are the full per-weight files rather than the `latin-*` subsets: only
// the full ones carry `unicode-range`, which is what lets a browser download
// just the subsets it needs. Importing `latin-400` and `latin-ext-400`
// together would instead leave the browser using whichever came last — and a
// latin-ext face has no basic ASCII in it.
import '@fontsource/inter-tight/400.css';
import '@fontsource/inter-tight/500.css';
import '@fontsource/inter-tight/600.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/600.css';

import './styles/globals.css';
import './styles/calendar.css';
import './styles/list.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
