/**
 * Toast Notification Context
 * Provides app-wide toast notifications with auto-dismiss
 * Security: message content is rendered as plain text (no dangerouslySetInnerHTML)
 */

import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  useEffect,
} from 'react';
import { CheckCircle, AlertCircle, XCircle, Info, X, Trophy } from 'lucide-react';

// Allowed toast types — prevents arbitrary type injection
const ALLOWED_TYPES = new Set(['success', 'error', 'warning', 'info', 'achievement']);

const MAX_TOASTS = 5;
const DEFAULT_DURATION = 4000;
const MAX_MESSAGE_LENGTH = 200;

const ToastContext = createContext(null);

// ─── Individual Toast ────────────────────────────────────────────────────────

const TOAST_STYLES = {
  success: {
    container: 'bg-emerald-950 border-emerald-500/50 text-emerald-100',
    icon: CheckCircle,
    iconClass: 'text-emerald-400',
  },
  error: {
    container: 'bg-red-950 border-red-500/50 text-red-100',
    icon: XCircle,
    iconClass: 'text-red-400',
  },
  warning: {
    container: 'bg-yellow-950 border-yellow-500/50 text-yellow-100',
    icon: AlertCircle,
    iconClass: 'text-yellow-400',
  },
  info: {
    container: 'bg-blue-950 border-blue-500/50 text-blue-100',
    icon: Info,
    iconClass: 'text-blue-400',
  },
  achievement: {
    container: 'bg-purple-950 border-purple-400/60 text-purple-100',
    icon: Trophy,
    iconClass: 'text-yellow-400',
  },
};

const ToastItem = ({ toast, onDismiss }) => {
  const [visible, setVisible] = useState(false);
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    // Trigger enter animation on mount
    const t = setTimeout(() => setVisible(true), 10);
    return () => clearTimeout(t);
  }, []);

  const handleDismiss = useCallback(() => {
    setLeaving(true);
    setTimeout(() => onDismiss(toast.id), 300);
  }, [toast.id, onDismiss]);

  useEffect(() => {
    if (toast.duration > 0) {
      const timer = setTimeout(handleDismiss, toast.duration);
      return () => clearTimeout(timer);
    }
  }, [toast.duration, handleDismiss]);

  const style = TOAST_STYLES[toast.type] || TOAST_STYLES.info;
  const Icon = style.icon;

  return (
    <div
      role="alert"
      aria-live="assertive"
      className={`
        flex items-start gap-3 px-4 py-3 rounded-lg border shadow-2xl
        max-w-sm w-full pointer-events-auto transition-all duration-300
        ${style.container}
        ${visible && !leaving ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-8'}
      `}
    >
      <Icon size={18} className={`flex-shrink-0 mt-0.5 ${style.iconClass}`} />
      <div className="flex-1 min-w-0">
        {toast.title && (
          <p className="font-bold text-sm mb-0.5 uppercase tracking-wide">
            {toast.title}
          </p>
        )}
        <p className="text-sm opacity-90 leading-snug break-words">{toast.message}</p>
      </div>
      <button
        onClick={handleDismiss}
        aria-label="Dismiss notification"
        className="flex-shrink-0 opacity-50 hover:opacity-100 transition-opacity mt-0.5"
      >
        <X size={14} />
      </button>
    </div>
  );
};

// ─── Toast Container ─────────────────────────────────────────────────────────

const ToastContainer = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div
      aria-label="Notifications"
      className="fixed bottom-6 right-6 z-50 flex flex-col gap-2 items-end pointer-events-none"
    >
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
      ))}
    </div>
  );
};

// ─── Provider ────────────────────────────────────────────────────────────────

export const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([]);
  const counterRef = useRef(0);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(
    ({ message, title, type = 'info', duration = DEFAULT_DURATION }) => {
      // Security: validate type against whitelist, truncate message
      const safeType = ALLOWED_TYPES.has(type) ? type : 'info';
      const safeMessage = String(message).slice(0, MAX_MESSAGE_LENGTH);
      const safeTitle = title ? String(title).slice(0, 60) : undefined;

      const id = ++counterRef.current;
      const toast = {
        id,
        message: safeMessage,
        title: safeTitle,
        type: safeType,
        duration,
      };

      setToasts((prev) => {
        const next = [...prev, toast];
        // Cap at MAX_TOASTS, dropping oldest
        return next.length > MAX_TOASTS ? next.slice(next.length - MAX_TOASTS) : next;
      });

      return id;
    },
    []
  );

  // Convenience helpers
  const toast = {
    success: (message, options = {}) =>
      addToast({ message, type: 'success', ...options }),
    error: (message, options = {}) =>
      addToast({ message, type: 'error', ...options }),
    warning: (message, options = {}) =>
      addToast({ message, type: 'warning', ...options }),
    info: (message, options = {}) =>
      addToast({ message, type: 'info', ...options }),
    achievement: (message, options = {}) =>
      addToast({ message, type: 'achievement', duration: 6000, ...options }),
  };

  return (
    <ToastContext.Provider value={{ addToast, removeToast, toast }}>
      {children}
      <ToastContainer toasts={toasts} onDismiss={removeToast} />
    </ToastContext.Provider>
  );
};

// ─── Hook ────────────────────────────────────────────────────────────────────

export const useToast = () => {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
};

export default ToastContext;
