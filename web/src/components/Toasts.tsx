import { X } from 'lucide-react';
import { useFira } from '../store';

export function Toasts() {
  const toasts = useFira((s) => s.toasts);
  const dismiss = useFira((s) => s.dismissToast);
  if (toasts.length === 0) return null;
  return (
    <div className="toasts">
      {toasts.map((t) => (
        <div key={t.id} className="toast" data-kind={t.kind}>
          <span className="toast-msg">{t.message}</span>
          <button
            className="toast-x"
            onClick={() => dismiss(t.id)}
            title="Dismiss"
            aria-label="Dismiss"
          >
            <X size={14} strokeWidth={2} />
          </button>
        </div>
      ))}
    </div>
  );
}
