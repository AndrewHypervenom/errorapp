import React from 'react';

function Overlay({ isVisible, onClick }) {
  if (!isVisible) return null;

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 transition-opacity lg:hidden z-20"
      onClick={onClick}
      aria-hidden="true"
    />
  );
}

export default Overlay;