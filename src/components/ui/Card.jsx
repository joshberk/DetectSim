/**
 * Card Component
 * Container with consistent styling
 */

import React from 'react';

export const Card = ({
  children,
  className = '',
  header,
  headerIcon: HeaderIcon,
  headerColor = 'emerald',
  footer,
  noPadding = false,
  ...props
}) => {
  const headerColors = {
    emerald: 'text-emerald-400',
    blue: 'text-blue-400',
    yellow: 'text-yellow-400',
    red: 'text-red-400',
    purple: 'text-purple-400',
    gray: 'text-gray-400',
  };

  return (
    <div
      className={`bg-gray-800 border border-gray-700 rounded-xl shadow-2xl relative overflow-hidden ${className}`}
      {...props}
    >
      {/* Top gradient line */}
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-500 to-blue-500" />

      {/* Header */}
      {header && (
        <div className="px-6 py-4 border-b border-gray-700">
          <div className={`flex items-center gap-2 ${headerColors[headerColor]}`}>
            {HeaderIcon && <HeaderIcon size={20} />}
            <h2 className="text-lg font-bold text-white">{header}</h2>
          </div>
        </div>
      )}

      {/* Content */}
      <div className={noPadding ? '' : 'p-6'}>{children}</div>

      {/* Footer */}
      {footer && (
        <div className="px-6 py-4 border-t border-gray-700 bg-gray-900/50">
          {footer}
        </div>
      )}
    </div>
  );
};

export default Card;
