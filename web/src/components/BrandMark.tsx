// Fira brand mark — same glyph as /public/favicon.svg, inlined so it can
// take a `size` prop and inherit gradient ids per instance.

interface Props {
  size?: number;
  className?: string;
  title?: string;
}

let gradSeq = 0;

export function BrandMark({ size = 32, className, title }: Props) {
  // Unique gradient id per instance so multiple marks on one page don't
  // collide if a future bundler tree-shakes oddly.
  const gid = `fira-grad-${gradSeq++}`;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label={title ?? 'Fira'}
    >
      <defs>
        <linearGradient id={gid} x1="22%" y1="8%" x2="78%" y2="92%">
          <stop offset="0%" stopColor="#8B5CF6" />
          <stop offset="100%" stopColor="#22D3EE" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="14" fill="#0F1024" />
      <path
        d="M20 14c0-3 2-5 6-5h18c4 0 5 2 3 5l-2 4c-1 1-3 2-5 2H28v8h10c3 0 4 2 3 4l-1 3c-1 1-3 2-5 2H28v14c0 3-2 4-4 4s-4-1-4-4z"
        fill={`url(#${gid})`}
      />
    </svg>
  );
}
