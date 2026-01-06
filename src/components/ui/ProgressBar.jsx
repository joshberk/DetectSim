/**
 * ProgressBar Component
 * Visual progress indicator
 */

import React from 'react';

const variants = {
  default: 'from-emerald-600 to-emerald-400',
  success: 'from-emerald-600 to-emerald-400',
  warning: 'from-yellow-600 to-yellow-400',
  danger: 'from-red-600 to-red-400',
  info: 'from-blue-600 to-blue-400',
  purple: 'from-purple-600 to-purple-400',
};

export const ProgressBar = ({
  value = 0,
  max = 100,
  variant = 'default',
  showLabel = false,
  label,
  size = 'md',
  animated = true,
  className = '',
}) => {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100));

  const heights = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3',
    xl: 'h-4',
  };

  return (
    <div className={className}>
      {(showLabel || label) && (
        <div className="flex justify-between text-xs mb-1">
          <span className="text-gray-400 font-bold uppercase tracking-wider">
            {label || 'Progress'}
          </span>
          <span className="text-emerald-400 font-mono">{Math.round(percentage)}%</span>
        </div>
      )}
      <div
        className={`${heights[size]} bg-gray-900 rounded-full overflow-hidden border border-gray-700`}
      >
        <div
          className={`h-full bg-gradient-to-r ${variants[variant]} rounded-full ${
            animated ? 'transition-all duration-1000' : ''
          }`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
};

export default ProgressBar;
