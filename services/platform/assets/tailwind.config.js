/** @type {import('tailwindcss').Config} */
module.exports = {
  // ===============================================================================
  // 🇷🇴 PRAHO PLATFORM - TAILWIND CONFIGURATION
  // ===============================================================================
  // Romanian hosting provider design system with strategic seams for Hugo migration

  content: [
    // Django templates
    '../templates/**/*.html',
    '../ui/templates/**/*.html',
    '../apps/**/templates/**/*.html',

    // Python files with Tailwind classes
    '../apps/**/*.py',
    '../ui/**/*.py',

    // JavaScript files
    '../static/js/**/*.js',
    './js/**/*.js',

    // Future Hugo migration path
    '../hugo/**/*.html',
    '../hugo/**/*.md',
  ],

  // Dark mode configuration (Romanian user preference)
  darkMode: 'class', // Enable class-based dark mode

  theme: {
    extend: {
      // ===============================================================================
      // 🎨 ROMANIAN BRAND COLORS
      // ===============================================================================
      colors: {
        // Primary brand colors - Romanian hosting theme
        primary: {
          50: 'hsl(220 90% 97%)',
          100: 'hsl(220 90% 94%)',
          200: 'hsl(220 90% 87%)',
          300: 'hsl(220 90% 78%)',
          400: 'hsl(220 90% 67%)',
          500: 'hsl(220 90% 56%)',  // Main brand color
          600: 'hsl(220 90% 45%)',
          700: 'hsl(220 90% 36%)',
          800: 'hsl(220 90% 28%)',
          900: 'hsl(220 90% 22%)',
          950: 'hsl(220 90% 14%)',
        },

        // Romanian flag accent colors
        'romanian-red': '#ce1126',
        'romanian-blue': '#002b7f',
        'romanian-yellow': '#fcd116',

        // Background colors for dark Romanian hosting dashboard
        bg: {
          DEFAULT: '#0b0c10',
          subtle: '#111217',
          muted: '#1a1b23',
          elevated: '#24252d',
        },

        // Content colors
        content: {
          DEFAULT: '#e6e8eb',
          subtle: '#b8bcc8',
          muted: '#9ca0ab',
          inverse: '#0b0c10',
        },

        // Border colors
        border: {
          DEFAULT: '#313449',
          subtle: '#24252d',
          strong: '#404354',
        },

        // Romanian business status colors
        success: {
          DEFAULT: '#10b981',
          bg: '#064e3b',
          border: '#065f46',
          content: '#d1fae5',
        },
        warning: {
          DEFAULT: '#f59e0b',
          bg: '#78350f',
          border: '#92400e',
          content: '#fef3c7',
        },
        error: {
          DEFAULT: '#ef4444',
          bg: '#7f1d1d',
          border: '#991b1b',
          content: '#fee2e2',
        },
        info: {
          DEFAULT: '#3b82f6',
          bg: '#1e3a8a',
          border: '#1d4ed8',
          content: '#dbeafe',
        },

        // Romanian currency colors
        currency: {
          ron: 'hsl(220 90% 56%)',
          eur: '#0066cc',
          usd: '#10b981',
        },

        // VAT status colors
        vat: {
          valid: '#10b981',
          invalid: '#ef4444',
          pending: '#f59e0b',
        },

        // Server status colors
        server: {
          online: '#10b981',
          offline: '#ef4444',
          maintenance: '#f59e0b',
          provisioning: '#3b82f6',
        },
      },

      // ===============================================================================
      // 🎯 TYPOGRAPHY (Romanian Language Optimized)
      // ===============================================================================
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          '"Noto Sans"',
          'Ubuntu',
          'sans-serif',
        ],
        mono: [
          '"JetBrains Mono"',
          '"Fira Code"',
          'Consolas',
          '"Liberation Mono"',
          'Menlo',
          'monospace',
        ],
      },

      fontSize: {
        'xs': ['0.75rem', { lineHeight: '1.5' }],     // 12px
        'sm': ['0.875rem', { lineHeight: '1.5' }],    // 14px
        'base': ['1rem', { lineHeight: '1.6' }],      // 16px - optimized for Romanian
        'lg': ['1.125rem', { lineHeight: '1.6' }],    // 18px
        'xl': ['1.25rem', { lineHeight: '1.5' }],     // 20px
        '2xl': ['1.5rem', { lineHeight: '1.4' }],     // 24px
        '3xl': ['1.875rem', { lineHeight: '1.3' }],   // 30px
        '4xl': ['2.25rem', { lineHeight: '1.2' }],    // 36px
      },

      // ===============================================================================
      // 📏 SPACING & LAYOUT
      // ===============================================================================
      spacing: {
        '18': '4.5rem',   // 72px
        '88': '22rem',    // 352px
        '100': '25rem',   // 400px
        '112': '28rem',   // 448px
        '128': '32rem',   // 512px
      },

      // Border radius for Romanian design language
      borderRadius: {
        'sm': '0.375rem',   // 6px
        DEFAULT: '0.75rem', // 12px
        'lg': '1rem',       // 16px
        'xl': '1.5rem',     // 24px
      },

      // ===============================================================================
      // 🎬 ANIMATIONS & TRANSITIONS
      // ===============================================================================
      animation: {
        'romanian-fade-in': 'romanian-fade-in 0.3s ease-out',
        'romanian-slide-up': 'romanian-slide-up 0.3s ease-out',
        'romanian-pulse': 'romanian-pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 3s linear infinite',
      },

      keyframes: {
        'romanian-fade-in': {
          '0%': {
            opacity: '0',
            transform: 'translateY(10px)',
          },
          '100%': {
            opacity: '1',
            transform: 'translateY(0)',
          },
        },
        'romanian-slide-up': {
          '0%': {
            opacity: '0',
            transform: 'translateY(20px)',
          },
          '100%': {
            opacity: '1',
            transform: 'translateY(0)',
          },
        },
        'romanian-pulse': {
          '0%, 100%': {
            opacity: '1',
          },
          '50%': {
            opacity: '0.5',
          },
        },
      },

      // Duration for Romanian UX (slightly slower for clarity)
      transitionDuration: {
        '150': '150ms',
        '250': '250ms',
        '500': '500ms',
      },

      // ===============================================================================
      // 📦 BOX SHADOWS
      // ===============================================================================
      boxShadow: {
        'sm': '0 1px 2px rgb(0 0 0 / 0.1)',
        DEFAULT: '0 4px 6px rgb(0 0 0 / 0.1)',
        'lg': '0 10px 15px rgb(0 0 0 / 0.1)',
        'xl': '0 20px 25px rgb(0 0 0 / 0.1)',
        'romanian': '0 4px 14px rgb(30 64 175 / 0.1)',
        'romanian-lg': '0 10px 25px rgb(30 64 175 / 0.15)',
      },

      // ===============================================================================
      // 📱 BREAKPOINTS (Romanian Mobile Usage)
      // ===============================================================================
      screens: {
        'xs': '475px',    // Extra small devices
        'sm': '640px',    // Small devices (landscape phones)
        'md': '768px',    // Medium devices (tablets)
        'lg': '1024px',   // Large devices (laptops/desktops)
        'xl': '1280px',   // Extra large devices (large laptops)
        '2xl': '1536px',  // 2X large devices (larger desktops)
      },

      // ===============================================================================
      // 🎨 BACKGROUND PATTERNS (Romanian Hosting Themes)
      // ===============================================================================
      backgroundImage: {
        'gradient-romanian': 'linear-gradient(135deg, hsl(220 90% 56%) 0%, hsl(220 90% 45%) 100%)',
        'gradient-success': 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
        'gradient-warning': 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
        'gradient-error': 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
        'dot-pattern': 'radial-gradient(circle, #313449 1px, transparent 1px)',
      },

      // ===============================================================================
      // 🔲 Z-INDEX SCALE
      // ===============================================================================
      zIndex: {
        '60': '60',
        '70': '70',
        '80': '80',
        '90': '90',
        '100': '100',
        'dropdown': '1000',
        'sticky': '1020',
        'fixed': '1030',
        'modal-backdrop': '1040',
        'modal': '1050',
        'popover': '1060',
        'tooltip': '1070',
        'toast': '1080',
      },

      // ===============================================================================
      // 📐 ASPECT RATIOS
      // ===============================================================================
      aspectRatio: {
        'invoice': '210 / 297',  // A4 ratio for Romanian invoices
        'card': '3 / 2',         // Credit card ratio
        'logo': '16 / 9',        // Logo ratio
      },
    },
  },

  // ===============================================================================
  // 🔌 PLUGINS
  // ===============================================================================
  plugins: [
    // Forms plugin for better form styling
    require('@tailwindcss/forms')({
      strategy: 'class', // Use class-based form styling
    }),

    // Typography plugin for content areas
    require('@tailwindcss/typography'),

    // Aspect ratio plugin
    require('@tailwindcss/aspect-ratio'),

    // Container queries plugin
    require('@tailwindcss/container-queries'),

    // Custom Romanian business utilities
    function ({ addUtilities, theme }) {
      const newUtilities = {
        // Romanian currency utilities
        '.currency-ron': {
          '&::after': {
            content: '" lei"',
            fontWeight: theme('fontWeight.normal'),
            color: theme('colors.content.subtle'),
          },
        },
        '.currency-eur': {
          '&::before': {
            content: '"€"',
            marginRight: '0.125rem',
          },
        },

        // Romanian VAT utilities
        '.vat-valid': {
          color: theme('colors.success.DEFAULT'),
          fontWeight: theme('fontWeight.medium'),
        },
        '.vat-invalid': {
          color: theme('colors.error.DEFAULT'),
          fontWeight: theme('fontWeight.medium'),
        },

        // Romanian server status utilities
        '.server-online': {
          color: theme('colors.server.online'),
        },
        '.server-offline': {
          color: theme('colors.server.offline'),
        },
        '.server-maintenance': {
          color: theme('colors.server.maintenance'),
        },

        // Romanian hover effects
        '.hover-romanian': {
          '&:hover': {
            backgroundColor: theme('colors.bg.muted'),
            borderColor: theme('colors.primary.500'),
            transition: 'all 0.2s ease',
          },
        },

        // Romanian focus effects
        '.focus-romanian': {
          '&:focus': {
            outline: `2px solid ${theme('colors.primary.500')}`,
            outlineOffset: '2px',
            borderRadius: theme('borderRadius.sm'),
          },
        },
      };

      addUtilities(newUtilities);
    },
  ],

  // ===============================================================================
  // ⚡ OPTIMIZATION
  // ===============================================================================
  corePlugins: {
    // Disable unused core plugins for smaller bundle size
    preflight: true,
    container: false, // Using custom container
  },

  // Future flag for CSS optimization
  future: {
    hoverOnlyWhenSupported: true,
  },

  // Experimental features
  experimental: {
    optimizeUniversalDefaults: true,
  },
};
