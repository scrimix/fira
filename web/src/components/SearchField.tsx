import { Search, X } from 'lucide-react';
import type { InputHTMLAttributes } from 'react';

// Shared filter / search input: leading search icon, clear (×) button when
// it holds a value, and a visually hidden label. Styled by `.search-field`
// + `.input` in globals.css.
export function SearchField({
  value,
  onValueChange,
  label,
  className,
  size = 'md',
  ...rest
}: Omit<InputHTMLAttributes<HTMLInputElement>, 'value' | 'size'> & {
  value: string;
  onValueChange: (v: string) => void;
  label: string;
  size?: 'md' | 'lg';
}) {
  return (
    <label className={`search-field${className ? ` ${className}` : ''}`} data-size={size}>
      <span className="sr-only">{label}</span>
      <Search size={13} strokeWidth={1.5} className="search-field-icon" aria-hidden />
      <input
        {...rest}
        className="input"
        value={value}
        onChange={(e) => onValueChange(e.target.value)}
        spellCheck={false}
      />
      {value && (
        <button type="button" className="search-field-clear" aria-label="Clear"
                onClick={() => onValueChange('')}>
          <X size={12} strokeWidth={1.5} />
        </button>
      )}
    </label>
  );
}
