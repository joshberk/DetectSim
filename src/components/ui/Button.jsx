/**
 * Button Component
 * Reusable button with variants
 */

import React from 'react';

const variants = {
  primary:
    'bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.3)] hover:shadow-[0_0_25px_rgba(16,185,129,0.5)]',
  secondary:
    'bg-gray-700 hover:bg-gray-600 text-gray-200 border border-gray-600',
  danger:
    'bg-red-600 hover:bg-red-500 text-white shadow-[0_0_15px_rgba(239,68,68,0.3)]',
  ghost:
    'bg-transparent hover:bg-gray-700 text-gray-400 hover:text-white',
  outline:
    'bg-transparent border border-gray-600 hover:border-emerald-500 text-gray-300 hover:text-emerald-400',
};

const sizes = {
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-4 py-2 text-sm',
  lg: 'px-6 py-3 text-base',
  xl: 'px-8 py-4 text-lg',
};

export const Button = ({
  children,
  variant = 'primary',
  size = 'md',
  disabled = false,
  loading = false,
  icon: Icon,
  iconPosition = 'left',
  className = '',
  onClick,
  type = 'button',
  ...props
}) => {
  const baseStyles =
    'inline-flex items-center justify-center font-bold rounded-lg transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-500 focus:ring-offset-gray-900 active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100';

  return (
    <button
      type={type}
      disabled={disabled || loading}
      onClick={onClick}
      className={`${baseStyles} ${variants[variant]} ${sizes[size]} ${className}`}
      {...props}
    >
      {loading ? (
        <>
          <svg
            className="animate-spin -ml-1 mr-2 h-4 w-4"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
          Loading...
        </>
      ) : (
        <>
          {Icon && iconPosition === 'left' && (
            <Icon size={size === 'sm' ? 14 : size === 'lg' ? 20 : 16} className="mr-2" />
          )}
          {children}
          {Icon && iconPosition === 'right' && (
            <Icon size={size === 'sm' ? 14 : size === 'lg' ? 20 : 16} className="ml-2" />
          )}
        </>
      )}
    </button>
  );
};

export default Button;
