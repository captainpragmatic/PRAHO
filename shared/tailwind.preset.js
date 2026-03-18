/** @type {import('tailwindcss').Config} */
/**
 * Shared Tailwind CSS preset for PRAHO design system.
 *
 * Contains tokens shared by both Platform and Portal services.
 * Service-specific configs extend this preset with their own overrides.
 */
module.exports = {
  darkMode: 'class',

  theme: {
    extend: {
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          'Ubuntu',
          'sans-serif',
        ],
        mono: [
          'Consolas',
          '"Liberation Mono"',
          'Menlo',
          'monospace',
        ],
      },

      // Shared status colors (DEFAULT values identical across services)
      colors: {
        success: '#10b981',
        warning: '#f59e0b',
        error: '#ef4444',
        info: '#3b82f6',
      },

      animation: {
        'fade-in': 'fade-in 0.3s ease-out',
        'slide-up': 'slide-up 0.3s ease-out',
      },

      keyframes: {
        'fade-in': {
          '0%': {
            opacity: '0',
            transform: 'translateY(10px)',
          },
          '100%': {
            opacity: '1',
            transform: 'translateY(0)',
          },
        },
        'slide-up': {
          '0%': {
            opacity: '0',
            transform: 'translateY(20px)',
          },
          '100%': {
            opacity: '1',
            transform: 'translateY(0)',
          },
        },
      },
    },
  },

  plugins: [
    require('@tailwindcss/forms')({
      strategy: 'class',
    }),
    require('@tailwindcss/typography'),
  ],
};
