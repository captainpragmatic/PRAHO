/** @type {import('tailwindcss').Config} */
module.exports = {
  // Portal-specific Tailwind configuration
  content: [
    // Portal templates
    './services/portal/templates/**/*.html',
    './services/portal/portal/**/templates/**/*.html',

    // Portal Python files with Tailwind classes
    './services/portal/**/*.py',

    // Portal JavaScript files
    './services/portal/static/js/**/*.js',
    './services/portal/assets/js/**/*.js',
  ],

  darkMode: 'class',

  theme: {
    extend: {
      colors: {
        // Customer-facing colors (softer, more welcoming)
        primary: {
          50: 'hsl(210 100% 97%)',
          100: 'hsl(210 100% 94%)',
          200: 'hsl(210 100% 87%)',
          300: 'hsl(210 100% 78%)',
          400: 'hsl(210 100% 67%)',
          500: 'hsl(210 100% 56%)',
          600: 'hsl(210 100% 45%)',
          700: 'hsl(210 100% 36%)',
          800: 'hsl(210 100% 28%)',
          900: 'hsl(210 100% 22%)',
          950: 'hsl(210 100% 14%)',
        },

        // Portal-specific colors
        portal: {
          bg: '#ffffff',
          'bg-dark': '#1a1b23',
          text: '#1f2937',
          'text-dark': '#e6e8eb',
          border: '#e5e7eb',
          'border-dark': '#313449',
        },

        // Status colors for customer portal
        success: '#10b981',
        warning: '#f59e0b',
        error: '#ef4444',
        info: '#3b82f6',
      },

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
