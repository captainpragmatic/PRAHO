# PRAHO Platform Architecture Diagrams

This directory contains Mermaid diagrams documenting the PRAHO platform architecture.

## Diagrams

### 1. System Overview

**File**: `diagrams/system-overview.mmd`

**Purpose**: High-level view of all services, databases, and external integrations.

**Shows**:
- Portal service (customer-facing, SQLite sessions only)
- Platform service (business logic, PostgreSQL)
- External integrations (Virtualmin, Stripe, ANAF, ROTLD)
- Network boundaries and data flows

**View online**: Copy the diagram content and paste into [Mermaid Live Editor](https://mermaid.live)

---

### 2. Data Flow

**File**: `diagrams/data-flow.mmd`

**Purpose**: Sequence diagram showing Portal ↔ Platform communication patterns.

**Shows**:
- Customer authentication flow (login, session creation)
- Data retrieval via HMAC-signed API requests
- Security isolation (Portal cannot access PostgreSQL directly)
- Session storage in Portal's SQLite vs business data in Platform's PostgreSQL

**Use case**: Understanding how the two services communicate securely.

---

### 3. Deployment Architecture

**File**: `diagrams/deployment.mmd`

**Purpose**: Docker network topology and container layout.

**Shows**:
- Docker network segmentation (`platform-network` vs `api-network`)
- Service exposure (Nginx reverse proxy, SSL termination)
- Database isolation (PostgreSQL only accessible from platform-network)
- External API access patterns

**Use case**: Setting up production deployment or understanding security boundaries.

---

### 4. App Dependencies

**File**: `diagrams/app-dependencies.mmd`

**Purpose**: Inter-app dependency graph showing how the 17 platform apps relate to each other.

**Shows**:
- Four dependency tiers: Foundation, Core Business, Specialized, Leaf
- Import relationships between apps (A → B means A depends on B)
- Hub apps (common, audit, settings) omitted for clarity — they connect to everything

**Use case**: Understanding coupling between apps, planning refactoring scope, or evaluating microservices extraction candidates.

---

### 5. Entity Relationships

**File**: `diagrams/entity-relationships.mmd`

**Purpose**: Database ER diagram showing core entities, key fields, and cardinality.

**Shows**:
- ~20 core entities grouped by domain (auth, business, catalog, orders, billing, hosting, domains, support, audit)
- Primary keys, foreign keys, status fields, and monetary fields
- Relationship cardinality (one-to-one, one-to-many, optional)
- PK strategy (UUID vs auto-increment) and monetary storage (cents as BigInteger)

**Use case**: Understanding the data model, writing queries, or planning schema migrations.

---

## Viewing Diagrams

### Option 1: Mermaid Live Editor

1. Go to [mermaid.live](https://mermaid.live)
2. Copy the contents of any `.mmd` file
3. Paste into the editor
4. View/export the rendered diagram

### Option 2: VS Code Extension

Install the [Mermaid Preview](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid) extension.

Open any `.mmd` file and click the preview icon.

### Option 3: GitHub

GitHub natively renders Mermaid diagrams in markdown. Create a `.md` file with:

\`\`\`mermaid
[paste diagram content here]
\`\`\`

### Option 4: CLI Rendering (Local)

Install Mermaid CLI:

```bash
npm install -g @mermaid-js/mermaid-cli
```

Render to PNG:

```bash
mmdc -i diagrams/system-overview.mmd -o diagrams/system-overview.png
```

### Option 5: Generate PNGs (API-based)

Generate PNG images locally using [mermaid.ink](https://mermaid.ink) API (PNGs are gitignored):

```bash
cd docs/architecture/diagrams

# Regenerate all diagrams
for diagram in *.mmd; do
  name="${diagram%.mmd}"
  encoded=$(cat "$diagram" | base64 -w0)
  curl -s "https://mermaid.ink/img/${encoded}" -o "${name}.png"
  echo "Generated ${name}.png"
done
```

Run this whenever you update the `.mmd` source files.

---

## Maintenance

**When to update these diagrams:**

- Adding a new service or external integration
- Changing network topology or Docker setup
- Modifying service communication patterns
- Updating security boundaries or authentication flows

**Versioning:**

These diagrams track the architecture version in `docs/ARCHITECTURE.md`. Current: **v1.2.0** (Feb 2026).

**Contributing:**

1. Edit the `.mmd` file directly
2. Test rendering in [mermaid.live](https://mermaid.live)
3. Update the diagram comment header with the change date
4. Include diagram updates in your PR description

---

## Related Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed written architecture guide
- [DEPLOYMENT.md](../deployment/DEPLOYMENT.md) - Production deployment instructions
- [ADRs](../ADRs/) - Architecture decision records
