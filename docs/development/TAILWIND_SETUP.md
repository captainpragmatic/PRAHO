# Tailwind CSS Setup for PRAHO Project

## 🎯 Overview
This project uses **Tailwind CSS v4** with local compilation for both Platform and Portal services.

## 🚀 Quick Start

### For New Team Members
```bash
# 1. Install dependencies
make install-frontend

# 2. Build CSS for all services
make build-css

# 3. Start development (with CSS watching)
make watch-css &
make dev
```

### Development Workflow

#### Build CSS (Production)
```bash
make build-css
```

#### Watch CSS (Development)
```bash
make watch-css
```
*Watches for changes and rebuilds automatically*

#### Using npm directly
```bash
npm run build-css    # Build for all services
npm run watch-css    # Watch portal only
```

## 📁 File Structure

```
input.css                                    # Source CSS file (edit this)
├── services/portal/assets/css/tailwind.min.css    # Portal compiled CSS
├── services/platform/static/css/tailwind.min.css  # Platform compiled CSS
└── package.json                             # Node.js dependencies
```

## 🔧 Configuration

- **Input file**: `input.css` (contains @import "tailwindcss" + custom styles)
- **Output files**: Automatically generated - **do not edit directly**
- **Version**: Tailwind CSS v4.1.13
- **Features**: Auto CSS generation, custom Romanian branding variables

## 🎨 Custom Styles

Romanian hosting brand variables are included:
```css
:root {
  --brand-h: 220;
  --brand-s: 90%;
  --brand-l: 56%;
  --bg: #0b0c10;
  --bg-elev: #111217;
  --content: #e6e8eb;
  --primary: hsl(var(--brand-h) var(--brand-s) var(--brand-l));
}
```

## 🔄 CI/CD Integration

Add to your CI pipeline:
```yaml
- run: npm install
- run: make build-css
```

## 📦 Dependencies

- **Node.js**: For running Tailwind CLI
- **tailwindcss**: v4.1.13 (automatically detects usage)

No configuration file needed - Tailwind v4 works out of the box! 🎉
