/**
 * Badge Component
 * Status indicators and labels
 */

import React from 'react';

const variants = {
  default: 'bg-gray-700 text-gray-300',
  success: 'bg-emerald-900/50 text-emerald-400 border border-emerald-500/30',
  warning: 'bg-yellow-900/50 text-yellow-400 border border-yellow-500/30',
  danger: 'bg-red-900/50 text-red-400 border border-red-500/30',
  info: 'bg-blue-900/50 text-blue-400 border border-blue-500/30',
  purple: 'bg-purple-900/50 text-purple-400 border border-purple-500/30',
};

const sizes = {
  sm: 'px-2 py-0.5 text-[10px]',
  md: 'px-2.5 py-1 text-xs',
  lg: 'px-3 py-1.5 text-sm',
};

export const Badge = ({
  children,
  variant = 'default',
  size = 'md',
  icon: Icon,
  className = '',
  ...props
}) => {
  return (
    <span
      className={`inline-flex items-center font-bold uppercase tracking-wider rounded ${variants[variant]} ${sizes[size]} ${className}`}
      {...props}
    >
      {Icon && <Icon size={size === 'sm' ? 10 : 12} className="mr-1" />}
      {children}
    </span>
  );
};

export default Badge;
