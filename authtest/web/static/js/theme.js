/**
 * Theme toggle functionality for dark/light mode support.
 * Persists preference in localStorage and respects system preference.
 */
(function() {
  'use strict';

  const STORAGE_KEY = 'authtest-theme';
  const DARK_CLASS = 'dark';

  function getStoredTheme() {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      return null;
    }
  }

  function setStoredTheme(theme) {
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (e) {
      // localStorage not available
    }
  }

  function getSystemPreference() {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }
    return 'light';
  }

  function applyTheme(theme) {
    if (theme === 'dark') {
      document.documentElement.classList.add(DARK_CLASS);
    } else {
      document.documentElement.classList.remove(DARK_CLASS);
    }
    updateToggleButton(theme);
  }

  function updateToggleButton(theme) {
    const toggleBtn = document.getElementById('theme-toggle');
    const sunIcon = document.getElementById('theme-icon-sun');
    const moonIcon = document.getElementById('theme-icon-moon');

    if (!toggleBtn || !sunIcon || !moonIcon) return;

    if (theme === 'dark') {
      sunIcon.classList.remove('hidden');
      moonIcon.classList.add('hidden');
    } else {
      sunIcon.classList.add('hidden');
      moonIcon.classList.remove('hidden');
    }
  }

  function getCurrentTheme() {
    const stored = getStoredTheme();
    if (stored) {
      return stored;
    }
    return getSystemPreference();
  }

  function toggleTheme() {
    const current = document.documentElement.classList.contains(DARK_CLASS) ? 'dark' : 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    setStoredTheme(next);
    applyTheme(next);
  }

  // Apply theme immediately on script load (before DOM ready to avoid flash)
  applyTheme(getCurrentTheme());

  // Set up toggle button when DOM is ready
  document.addEventListener('DOMContentLoaded', function() {
    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', toggleTheme);
    }
    // Update icons after DOM is ready
    updateToggleButton(getCurrentTheme());
  });

  // Listen for system preference changes
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
      // Only auto-switch if no stored preference
      if (!getStoredTheme()) {
        applyTheme(e.matches ? 'dark' : 'light');
      }
    });
  }

  // Expose toggle function globally for inline handlers if needed
  window.toggleTheme = toggleTheme;
})();
