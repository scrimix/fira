import { useEffect, useRef, useState } from 'react';
import { Binary, FileText, Loader2 } from 'lucide-react';
import { useFira } from '../store';

export const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024; // 10 MB

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${Math.ceil(bytes / 1024)} KB`;
}

// A not-yet-uploaded attachment: either typed/pasted text, or bytes that
// arrived through the clipboard.
export type AttachmentDraft =
  | { kind: 'text'; filename: string; text: string }
  | { kind: 'image' | 'binary'; filename: string; blob: Blob };

const IMAGE_EXT_BY_MIME: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/gif': 'gif',
  'image/webp': 'webp',
  'image/avif': 'avif',
  'image/bmp': 'bmp',
  'image/svg+xml': 'svg',
};

const MIME_BY_EXT: Record<string, string> = {
  txt: 'text/plain', log: 'text/plain', csv: 'text/csv', tsv: 'text/tab-separated-values',
  md: 'text/markdown', markdown: 'text/markdown', mdx: 'text/markdown',
  json: 'application/json', xml: 'application/xml', yml: 'text/yaml', yaml: 'text/yaml',
  html: 'text/html', htm: 'text/html', css: 'text/css',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', avif: 'image/avif', bmp: 'image/bmp', svg: 'image/svg+xml',
  pdf: 'application/pdf', zip: 'application/zip',
};

// Raster formats we can hand to <canvas>. Anything else keeps its bytes.
const REENCODABLE = new Set(['image/png', 'image/jpeg', 'image/webp']);

// Text files small enough to open straight in the editor instead of
// showing them as opaque bytes.
const INLINE_TEXT_LIMIT = 512 * 1024;

function extOf(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
}

// Path components and control characters never survive into a file name;
// the server applies the same rule (and a stricter one to the extension,
// which is what it builds the storage path from).
function sanitizeFilename(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? '';
  // eslint-disable-next-line no-control-regex
  return base.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 120).replace(/^\.+/, '');
}

function withExtension(name: string, fallbackExt: string): string {
  return extOf(name) ? name : `${name}.${fallbackExt}`;
}

function stamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

function isEditable(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el || !el.tagName) return false;
  return el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable;
}

function looksTextual(type: string, filename: string): boolean {
  if (type.startsWith('text/')) return true;
  if (type === 'application/json' || type === 'application/xml') return true;
  if (type === '' || type === 'application/octet-stream') {
    const ext = extOf(filename);
    return ext !== '' && MIME_BY_EXT[ext]?.startsWith('text/') === true;
  }
  return false;
}

export function emptyTextDraft(): AttachmentDraft {
  return { kind: 'text', filename: `note-${stamp()}.txt`, text: '' };
}

export function draftFromFile(file: File): AttachmentDraft {
  const named = sanitizeFilename(file.name);
  if (file.type.startsWith('image/')) {
    const ext = IMAGE_EXT_BY_MIME[file.type] ?? 'png';
    return { kind: 'image', filename: withExtension(named || `image-${stamp()}`, ext), blob: file };
  }
  return { kind: 'binary', filename: withExtension(named || `file-${stamp()}`, 'bin'), blob: file };
}

// Turns a paste into a draft, or null when the paste should keep its normal
// meaning (plain text landing in an input, empty clipboard).
export function draftFromPaste(e: ClipboardEvent): AttachmentDraft | null {
  const dt = e.clipboardData;
  if (!dt) return null;

  const file = Array.from(dt.items).find((i) => i.kind === 'file')?.getAsFile() ?? dt.files[0] ?? null;
  if (file) return draftFromFile(file);

  if (isEditable(e.target)) return null;
  const text = dt.getData('text/plain');
  if (!text.trim()) return null;
  return { kind: 'text', filename: `pasted-${stamp()}.txt`, text };
}

// Repaints through a canvas so the bytes actually match the extension the
// user picked (a .jpg that is really a PNG confuses downstream tools).
async function encodeImage(blob: Blob, targetMime: string): Promise<Blob> {
  const bitmap = await createImageBitmap(blob);
  try {
    const canvas = document.createElement('canvas');
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('no 2d context');
    // JPEG has no alpha — flatten onto white instead of onto black.
    if (targetMime === 'image/jpeg') {
      ctx.fillStyle = '#fff';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
    }
    ctx.drawImage(bitmap, 0, 0);
    const out = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob(resolve, targetMime, 0.92),
    );
    if (!out) throw new Error('encode failed');
    return out;
  } finally {
    bitmap.close();
  }
}

interface Props {
  taskId: string;
  draft: AttachmentDraft;
  /** Head breadcrumb: "project / task". */
  crumb: string;
  projectColor: string;
  onClose: () => void;
}

export function AttachmentComposer({ taskId, draft: initial, crumb, projectColor, onClose }: Props) {
  const [draft, setDraft] = useState<AttachmentDraft>(initial);
  const [filename, setFilename] = useState(initial.filename);
  const [dims, setDims] = useState<{ w: number; h: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const addAttachment = useFira((s) => s.addAttachment);
  const pollChanges = useFira((s) => s.pollChanges);
  const nameRef = useRef<HTMLInputElement>(null);
  const textRef = useRef<HTMLTextAreaElement>(null);

  // Pasted text files are more useful open in the editor than as bytes.
  useEffect(() => {
    if (draft.kind !== 'binary') return;
    if (draft.blob.size > INLINE_TEXT_LIMIT || !looksTextual(draft.blob.type, draft.filename)) return;

    let cancelled = false;
    const blob = draft.blob;
    blob.text()
      .then((text) => { if (!cancelled) setDraft({ kind: 'text', filename: draft.filename, text }); })
      .catch(() => { /* keep the binary view */ });
    return () => { cancelled = true; };
  }, [draft]);

  // Preview URL for image drafts, revoked when the draft or modal goes away.
  // Created in the effect (not a memo) so a StrictMode remount re-creates it
  // instead of rendering an already-revoked URL.
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  useEffect(() => {
    if (draft.kind !== 'image') { setImageUrl(null); return; }
    const url = URL.createObjectURL(draft.blob);
    setImageUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [draft]);

  useEffect(() => {
    if (draft.kind === 'text' && draft.text === '') textRef.current?.focus();
    else nameRef.current?.select();
  }, []);

  const size = draft.kind === 'text' ? new Blob([draft.text]).size : draft.blob.size;
  const sourceMime = draft.kind === 'text' ? '' : draft.blob.type;
  const defaultExt = draft.kind === 'text'
    ? 'txt'
    : draft.kind === 'image'
      ? IMAGE_EXT_BY_MIME[sourceMime] ?? 'png'
      : 'bin';
  const finalName = withExtension(sanitizeFilename(filename), defaultExt);
  const targetMime = MIME_BY_EXT[extOf(finalName)]
    ?? (draft.kind === 'text' ? 'text/plain' : sourceMime || 'application/octet-stream');
  // Renaming .png → .jpg re-encodes rather than mislabelling the bytes.
  // SVG is markup, not a raster the canvas can round-trip.
  const willConvert = draft.kind === 'image'
    && REENCODABLE.has(targetMime)
    && targetMime !== sourceMime
    && sourceMime !== 'image/svg+xml';

  const empty = draft.kind === 'text' ? draft.text.length === 0 : draft.blob.size === 0;
  const tooBig = size > MAX_ATTACHMENT_BYTES;
  const canSave = !saving && !empty && !tooBig && finalName.length > 1;

  const save = async () => {
    if (!canSave) return;
    setSaving(true);
    setError(null);
    try {
      let body: BlobPart;
      if (draft.kind === 'text') body = draft.text;
      else if (willConvert) body = await encodeImage(draft.blob, targetMime);
      else body = draft.blob;

      const file = new File([body], finalName, { type: targetMime });
      if (file.size > MAX_ATTACHMENT_BYTES) {
        setError(`${formatBytes(file.size)} — max is ${formatBytes(MAX_ATTACHMENT_BYTES)}.`);
        return;
      }
      await addAttachment(taskId, file);
      await pollChanges();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save the attachment.');
    } finally {
      setSaving(false);
    }
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); onClose(); }
      if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.stopPropagation(); e.preventDefault(); void save(); }
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  });

  const kindLabel = draft.kind === 'text'
    ? 'Text'
    : draft.kind === 'image'
      ? `${(IMAGE_EXT_BY_MIME[sourceMime] ?? 'image').toUpperCase()} image`
      : sourceMime || 'Binary';

  return (
    <div className="modal-backdrop confirm-backdrop" onClick={onClose}>
      <div
        className="modal ac-modal"
        style={{ ['--proj-color' as string]: projectColor }}
        onClick={(e) => e.stopPropagation()}
        onPaste={(e) => {
          // Inside the composer, a paste of bytes replaces the draft; text
          // pasted into the editor behaves normally.
          const next = draftFromPaste(e.nativeEvent);
          if (!next || next.kind === 'text') return;
          e.preventDefault();
          setDraft(next);
          setFilename(next.filename);
          setDims(null);
        }}
      >
        <div className="modal-head">
          <span className="proj-dot" style={{ background: projectColor }} />
          <span className="ext">{crumb} / New attachment</span>
        </div>

        <div className="ac-body">
          <label className="np-label" htmlFor="ac-filename">File name</label>
          <input
            id="ac-filename"
            ref={nameRef}
            className="np-title"
            value={filename}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setFilename(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void save(); } }}
          />
          <div className="ac-meta">
            <span>{kindLabel}</span>
            <span>·</span>
            <span>{formatBytes(size)}</span>
            {dims && <><span>·</span><span>{dims.w} × {dims.h}</span></>}
            {finalName !== filename && <><span>·</span><span>saved as {finalName}</span></>}
            {willConvert && <><span>·</span><span>converted to {extOf(finalName).toUpperCase()}</span></>}
          </div>

          <label className="np-label">Content</label>
          {draft.kind === 'text' && (
            <textarea
              ref={textRef}
              className="ac-text"
              value={draft.text}
              spellCheck={false}
              placeholder="Type or paste the file content…"
              onChange={(e) => setDraft({ kind: 'text', filename: draft.filename, text: e.target.value })}
            />
          )}
          {draft.kind === 'image' && (
            <div className="ac-preview">
              <img
                src={imageUrl ?? undefined}
                alt={finalName}
                className="ac-image"
                onLoad={(e) => setDims({
                  w: e.currentTarget.naturalWidth,
                  h: e.currentTarget.naturalHeight,
                })}
              />
            </div>
          )}
          {draft.kind === 'binary' && (
            <div className="ac-preview ac-binary">
              <Binary size={22} strokeWidth={1.5} />
              <div className="ac-binary-lines">
                <strong>{formatBytes(size)}</strong>
                <span>{sourceMime || 'unknown type'} — no preview available</span>
              </div>
            </div>
          )}

          {tooBig && (
            <div className="np-error">
              {formatBytes(size)} — max is {formatBytes(MAX_ATTACHMENT_BYTES)}.
            </div>
          )}
          {error && <div className="np-error">{error}</div>}
        </div>

        <div className="modal-footer">
          <span className="ac-hint">
            {draft.kind === 'text'
              ? <><FileText size={13} strokeWidth={1.75} /> Paste an image or a file to swap the content</>
              : <><FileText size={13} strokeWidth={1.75} /> Paste again to replace</>}
          </span>
          <button className="btn" onClick={onClose} disabled={saving}>Cancel</button>
          <button className="btn np-create" onClick={() => void save()} disabled={!canSave}>
            {saving ? <Loader2 size={13} strokeWidth={2} className="attachment-spin" /> : null}
            {saving ? 'Saving…' : 'Attach'}
          </button>
        </div>
      </div>
    </div>
  );
}
