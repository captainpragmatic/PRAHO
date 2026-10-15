# Tailwind CSS Setup

PRAHO compiles Tailwind CSS v4 locally for Platform and Portal. Run the commands below
from the repository root. The [Makefile](../../Makefile) is the main interface;
[package.json](../../package.json) declares dependencies and npm scripts, and
[package-lock.json](../../package-lock.json) pins the resolved versions.

## Install and Build

```bash
make install-frontend
make build-css
make dev
```

Node.js and npm are needed when building CSS. `make install-frontend` is an alias for
`make install-css`, which runs `npm install`. `make dev` also builds CSS before starting
the services; the explicit build above lets you check the asset step separately.

`make build-css` checks for the locally installed `@tailwindcss/cli` and uses
`npx --no-install`; install dependencies first. If npm is absent, this target deliberately
skips compilation and relies on the existing compiled assets. A successful skipped command
does not establish that a CSS edit was built.

## Sources and Outputs

| File | Role |
|---|---|
| [assets/css/platform.css](../../assets/css/platform.css) | Platform entry point: Tailwind import, shared partial, forms/typography plugins and Platform `@theme`. |
| [assets/css/portal.css](../../assets/css/portal.css) | Portal entry point: the same imports/plugins and the customer-facing `@theme`. |
| [assets/css/input.css](../../assets/css/input.css) | Shared tokens, utilities and styles imported by both entries. |
| [services/platform/static/css/tailwind.min.css](../../services/platform/static/css/tailwind.min.css) | Compiled Platform stylesheet. |
| [services/portal/static/css/tailwind.min.css](../../services/portal/static/css/tailwind.min.css) | Compiled Portal stylesheet. |

Edit the sources and rebuild; do not edit compiled output directly.
`input.css` is a partial, not a build entry point: it does not import Tailwind itself,
so building it directly omits the Tailwind utilities.

Template classes come from the service templates and `shared/ui/templates/`.
Run the shipped build from the root, where its normal source discovery takes place.
Django's `collectstatic` publishes the compiled files; it does not compile Tailwind.

## Watch During Development

Run a watcher in one terminal and the services in another:

```bash
make watch-css
```

```bash
make dev
```

`make watch-css` starts watchers for **both** entries: Portal in the background and Platform
in the foreground. This is a separate long-running command; `make dev` performs the initial
build but does not start a watcher.

The npm scripts have different watch scope:

```bash
npm run build-css    # Both services, minified
npm run watch-css    # Portal only
```

## CSS-First Theme and Shared Components

Both entry points use `@theme` and load `@tailwindcss/forms` and
`@tailwindcss/typography` with `@plugin`. Shared CSS variables and utility classes live in
`assets/css/input.css`; service palettes live in their entry points. The retired JavaScript
Tailwind configs are not inputs to the shipped build. See the amendment in
[ADR-0035](../ADRs/ADR-0035-unified-design-system.md).

Shared component templates live in `shared/ui/templates/components/`. Both services use
that canonical directory; CSS changes affecting a shared component should be checked in both.

Platform's primary scale uses HSL hue 220; Portal's uses 210. Edit the
`--color-primary-*` tokens in each entry point to change that service's palette.

## Versions and CI

Read dependency ranges from `package.json` and exact versions from `package-lock.json`.
Do not treat the old minimum `^4.1.13` range as the installed version; the lockfile currently
resolves both `tailwindcss` and `@tailwindcss/cli` to 4.3.3. To inspect a local install:

```bash
npm ls --depth=0 tailwindcss @tailwindcss/cli
```

The [nightly browser job](../../.github/workflows/nightly.yml) sets up Node and runs
`npm ci` before the E2E stack invokes `make build-css`. Keep the lockfile tracked for this
reproducible installation. Use `npm ci` for an equivalent clean install. The local
`make install-frontend` convenience target uses `npm install`; review any lockfile changes.
