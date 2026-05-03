import { useEffect, useState } from 'react';

// matchMedia subscription as a hook. Re-renders when the query flips.
// Mobile breakpoint is centralized here so all components answer the
// same question instead of each one inlining its own width threshold.
export function useMediaQuery(query: string): boolean {
  const [match, setMatch] = useState(() =>
    typeof window !== 'undefined' && window.matchMedia(query).matches,
  );
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia(query);
    const onChange = () => setMatch(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [query]);
  return match;
}

export function useIsMobile(): boolean {
  return useMediaQuery('(max-width: 700px)');
}
