/** @type {import('tailwindcss').Config} */
module.exports = {
  presets: [require('../../shared/tailwind.preset.js')],

  content: [
    // Portal templates
    './services/portal/templates/**/*.html',
    './services/portal/portal/**/templates/**/*.html',
    // Shared component templates
    './shared/ui/templates/**/*.html',
    // Portal Python files with Tailwind classes
    './services/portal/**/*.py',
    // Portal JavaScript files
    './services/portal/static/js/**/*.js',
    './services/portal/assets/js/**/*.js',
    // Shared JavaScript files
    './shared/ui/static/js/**/*.js',
  ],

  theme: {
    extend: {
      colors: {
        // Customer-facing primary (softer hue than Platform)
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

        // Portal-specific surface colors
        portal: {
          bg: '#ffffff',
          'bg-dark': '#1a1b23',
          text: '#1f2937',
          'text-dark': '#e6e8eb',
          border: '#e5e7eb',
          'border-dark': '#313449',
        },
      },

      fontSize: {
        'page-title': ['var(--font-size-page-title)', { lineHeight: 'var(--line-height-page-title)', fontWeight: 'var(--font-weight-page-title)' }],
        'section-title': ['var(--font-size-section-title)', { lineHeight: 'var(--line-height-section-title)', fontWeight: 'var(--font-weight-section-title)' }],
      },

      spacing: {
        'page-gutter': 'var(--space-page-gutter)',
        'section-stack': 'var(--space-section-stack)',
        'card-padding': 'var(--space-card-padding)',
        'field-stack': 'var(--space-field-stack)',
      },
    },
  },
};
