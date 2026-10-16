# duckJump Documentation & Landing Website

Static website and documentation for **duckJump**, built with [Astro](https://astro.build/) and [Tailwind CSS](https://tailwindcss.com/). Hosted on GitHub Pages.

## Local Development

From the repository root:

```bash
make website-dev      # Starts Astro development server
make website-build    # Builds static HTML/CSS to website/dist
```

Or from inside `website/`:

```bash
cd website
bun install
bun run dev          # http://localhost:4321/duckJump/
bun run build        # Generates output into dist/
bun run preview      # Previews the production build locally
```

## GitHub Pages Deployment

Deployment is automated via GitHub Actions in [`.github/workflows/deploy-pages.yml`](../.github/workflows/deploy-pages.yml). Any push to `main` touching `website/**` automatically builds and publishes the site to GitHub Pages.

## Structure

- `src/pages/index.astro`: Main landing page with Hero sandbox, feature matrix, Guacamole comparison, architecture flow, and quickstart.
- `src/pages/docs/`: Full documentation chapters:
  - `index.astro`: Getting started and distro installation.
  - `architecture.astro`: Gateway, Rust session daemons, and DJTP protocol.
  - `security.astro`: AES-256-GCM vault and host key pinning.
  - `pam-grants.astro`: Just-In-Time access grants and session termination.
  - `audit-logging.astro`: Tamper-evident SHA-256 and HMAC audit chains.
  - `edge-agents.astro`: Reverse WSS tunnels for closed networks.
  - `recordings-s3.astro`: Asciicast & graphical recordings with S3 storage.
  - `cli-configuration.astro`: Configuration environment and CLI reference.
  - `api.astro`: REST API and OpenAPI 3.1 contract.
- `public/brand/`: Official DuckJump logos and marks.
