<p align="center">
  <img src="https://img.shields.io/badge/Recall-AI%20Workspace-black?style=for-the-badge&labelColor=000" alt="Recall" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Next.js-16.1-000000?style=flat-square&logo=next.js&logoColor=white" alt="Next.js" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/TypeScript-5.7-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/CSS-Custom%20Properties-1572B6?style=flat-square&logo=css3&logoColor=white" alt="CSS" />
  <img src="https://img.shields.io/badge/Heroicons-2.x-8B5CF6?style=flat-square&logo=heroicons&logoColor=white" alt="Heroicons" />
  <img src="https://img.shields.io/badge/License-MIT-22C55E?style=flat-square" alt="License" />
</p>

<p align="center">
  A production-grade AI workspace platform inspired by Claude.com.<br/>
  Chat, Research, Code, Projects, Memory, Extensions — all features unlocked, no billing gates.
</p>

---

# Recall

Recall is a unified AI workspace that provides a complete interface for interacting with large language models. It combines real-time chat with streaming responses, deep research capabilities, a code editor with AI assistance, project management, persistent memory, and a full extension ecosystem — all within a single, polished web application.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Feature Pages](#feature-pages)
- [API Reference](#api-reference)
- [Design System](#design-system)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture Overview

Recall follows a modern full-stack architecture built on Next.js App Router.

```mermaid
graph TD
    Client["Client (Browser)"]
    NextJS["Next.js App Router"]
    
    subgraph Frontend [Frontend Layers]
        ClientComp["Client Components (React 19)"]
        ThemeProvider["ThemeProvider (Theming)"]
        LayoutShell["Sidebar + Topbar Shell"]
        FeaturePages["Feature Pages (Chat, Code, RAG, etc.)"]
    end
    
    subgraph Backend [Backend Services /lib]
        APIRoutes["API Route Handlers (/api/*)"]
        AuthService["Auth Service (JWT/Bcrypt)"]
        ClaudeSDK["Claude API Service (Anthropic)"]
        RAGPipeline["RAG Pipeline (Chunking/Retriever)"]
        MCPClient["MCP Client (JSON-RPC)"]
        Sandbox["Code Sandbox (Multi-runtime)"]
        DB["Database Layer (Prisma/Postgres)"]
    end
    
    Client --> NextJS
    NextJS --> Frontend
    NextJS --> Backend
    
    Frontend --> ThemeProvider
    Frontend --> LayoutShell
    LayoutShell --> FeaturePages
    
    Backend --> AuthService
    Backend --> ClaudeSDK
    Backend --> RAGPipeline
    Backend --> MCPClient
    Backend --> Sandbox
    Backend --> DB
```

### RAG System Architecture

The platform integrates a production-grade Retrieval-Augmented Generation pipeline:

**Ingestion Path** (offline):
Document Sources -> Ingestion Pipeline (OCR, chunking, metadata extraction) -> Embedding Service -> Vector DB / Index Layer

**Query Path** (online):
User Query -> API Gateway -> Embedding Service -> Vector DB -> Retriever Service -> Reranker -> Context Builder -> LLM Generator -> Cache -> User Response

**Operations**:
Orchestration, caching (LRU with TTL), logging, APM, feedback loops, and scheduled reindexing.

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Framework** | ![Next.js](https://img.shields.io/badge/Next.js-16.1-000?style=flat-square&logo=next.js&logoColor=white) | App Router, SSR, API routes |
| **UI Library** | ![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black) | Component architecture |
| **Language** | ![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?style=flat-square&logo=typescript&logoColor=white) | Type safety |
| **Styling** | ![CSS](https://img.shields.io/badge/CSS-Custom%20Properties-1572B6?style=flat-square&logo=css3&logoColor=white) | Design tokens, theming |
| **Icons** | ![Heroicons](https://img.shields.io/badge/Heroicons-2.x-8B5CF6?style=flat-square) | Outline + Solid icon system |
| **Font** | ![Google Fonts](https://img.shields.io/badge/Google%20Fonts-Inter-4285F4?style=flat-square&logo=google-fonts&logoColor=white) | Typography |
| **Bundler** | ![Turbopack](https://img.shields.io/badge/Turbopack-Latest-FF4785?style=flat-square) | Fast dev builds |
| **Package Manager** | ![npm](https://img.shields.io/badge/npm-10.x-CB3837?style=flat-square&logo=npm&logoColor=white) | Dependency management |

### Planned / Backend Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **LLM** | ![Claude](https://img.shields.io/badge/Claude-Opus%204.6-D4A373?style=flat-square) | Primary AI model |
| **Vector DB** | ![Pinecone](https://img.shields.io/badge/Pinecone-Managed-000?style=flat-square) | Production vector search |
| **Cache** | ![Redis](https://img.shields.io/badge/Redis-7.x-DC382D?style=flat-square&logo=redis&logoColor=white) | Response caching, sessions |
| **Database** | ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white) | Conversations, users, metadata |
| **Queue** | ![BullMQ](https://img.shields.io/badge/BullMQ-Latest-E8483A?style=flat-square) | Background job processing |
| **Auth** | ![JWT](https://img.shields.io/badge/JWT-RS256-000?style=flat-square&logo=json-web-tokens&logoColor=white) | Authentication |
| **Observability** | ![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-1.x-7B68EE?style=flat-square) | Tracing, metrics |
| **Container** | ![Docker](https://img.shields.io/badge/Docker-24-2496ED?style=flat-square&logo=docker&logoColor=white) | Containerization |
| **Orchestration** | ![Kubernetes](https://img.shields.io/badge/Kubernetes-1.28-326CE5?style=flat-square&logo=kubernetes&logoColor=white) | Production orchestration |
| **CDN** | ![Cloudflare](https://img.shields.io/badge/Cloudflare-CDN-F38020?style=flat-square&logo=cloudflare&logoColor=white) | Edge caching, DDoS protection |

---

---

## Getting Started

### Prerequisites

- Node.js 18.17 or later
- npm 9.x or later

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/recall.git
cd recall

# Install dependencies
npm install

# Start development server
npm run dev
```

The application will be available at `http://localhost:3000`.

### Build for Production

```bash
# Create optimized production build
npm run build

# Start production server
npm start
```

### Environment Variables

Create a `.env.local` file in the project root:

```env
# AI Model Configuration
ANTHROPIC_API_KEY=sk-ant-...
DEFAULT_MODEL=sonnet-4.6

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/recall
REDIS_URL=redis://localhost:6379

# Vector Database
PINECONE_API_KEY=your-key
PINECONE_INDEX=recall-production
PINECONE_ENVIRONMENT=us-east-1

# Authentication
JWT_SECRET=your-secret-key
JWT_EXPIRY=7d

# File Storage
S3_BUCKET=recall-uploads
S3_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret

# Feature Flags
ENABLE_EXTENDED_THINKING=true
ENABLE_TOOL_USE=true
ENABLE_WEB_SEARCH=true

# Observability
OTEL_ENDPOINT=https://otel-collector:4317
LOG_LEVEL=info
```

---

## Feature Pages

### Home (`/`)

The landing page provides a Claude-style greeting with a centered chat input, model selector (Opus / Sonnet / Haiku), Extended Thinking toggle, and quick action chips (Write, Learn, Code, Research, Analyze). The greeting adapts based on time of day.

### Chat (`/chat`)

Full-featured chat interface with:
- Conversation list sidebar with search and pinning
- Model selector with Extended Thinking toggle
- SSE streaming message display
- Markdown rendering in AI responses
- File attachment (PaperClipIcon) and image upload (PhotoIcon)
- Copy and regenerate actions per message
- Keyboard shortcut support (Enter to send, Shift+Enter for newline)

### Research (`/research`)

Multi-step AI research agent with:
- Topic input with depth selection (Quick / Deep / Multi-Source Synthesis)
- Real-time progress indicator during research
- Source list with relevance scoring
- Generated research report with copy and export actions
- Research job history

### Code (`/code`)

Three-panel code environment:
- **File Tree** (left): hierarchical folder/file navigation
- **Editor** (center): syntax-highlighted code display with tabs
- **AI Panel** (right): contextual code analysis with Explain, Refactor, Tests, Debug, and Run actions

### Projects (`/projects`)

Project management interface:
- Grid view of project cards with color-coded icons
- Search/filter functionality
- Create project modal with name and description
- Per-project file count, last updated timestamp
- Upload and settings actions per project

### Memory (`/memory`)

Persistent memory manager:
- Categorized memory entries (Preferences, Context, Infrastructure, Profile)
- Search across all memory keys and values
- Add, edit, and delete operations
- Auto-populated from conversation context

### Extensions (`/extensions`)

Extension marketplace:
- Chrome Extension, Excel Add-in, PowerPoint Add-in
- API Access, Slack Integration, VS Code Extension
- MCP Connectors, Google Workspace
- Connection status indicators (CheckCircleIcon for connected)
- Configure / Install / Documentation actions

### Settings (`/settings`)

Tabbed settings interface:
- **Profile**: Name, email, avatar upload
- **Models**: Default model selection with checkmark, Extended Thinking toggle, Tool Use toggle, Max Output Tokens slider
- **Appearance**: Theme picker (Light / Dark / System) with visual cards
- **API Keys**: Key table with create, rotate, and delete
- **Data and Privacy**: Memory toggle, training data opt-out, danger zone (export, delete)

### Admin (`/admin`)

Admin dashboard:
- Stats cards (Active Users, Messages Today, Avg Latency, Token Usage) with trend indicators
- User management table with role badges and status
- System health table with per-service status (operational / degraded)
- Reindex action per service

### Docs (`/docs`)

Searchable documentation page:
- Full-text search across all documentation sections
- Category-based navigation
- Expandable article cards
- Covers: Getting Started, Architecture, API Reference, Chat, Research, Code, Projects, Memory, Extensions, Settings, Admin, RAG Pipeline, Deployment, Security

---

## API Reference

All API routes return a consistent JSON envelope:

```json
{
  "success": true,
  "timestamp": "2026-03-01T12:00:00.000Z",
  "data": { ... }
}
```

Error responses:

```json
{
  "success": false,
  "error": "Error message",
  "timestamp": "2026-03-01T12:00:00.000Z"
}
```

### Core AI

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/chat` | Streaming chat completion (SSE) |
| `GET` | `/api/models` | List available models |
| `POST` | `/api/models` | Set default model |
| `GET` | `/api/features` | List all feature flags |

### Conversations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/conversations` | List conversations |
| `POST` | `/api/conversations` | Create conversation |
| `GET` | `/api/conversations/:id` | Get conversation by ID |
| `PATCH` | `/api/conversations/:id` | Update conversation (title, etc.) |
| `DELETE` | `/api/conversations/:id` | Delete conversation |

### Messages

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/messages?conversation_id=` | Get messages for a conversation |
| `POST` | `/api/messages` | Send a message |

### Research

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/research/run` | Start a research job |
| `GET` | `/api/research/:id` | Get research status and report |

### Code Tools

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/code/explain` | Explain code |
| `POST` | `/api/code/refactor` | Refactor code |
| `POST` | `/api/code/generate` | Generate code |
| `POST` | `/api/code/run` | Execute code in sandbox |
| `POST` | `/api/code/debug` | Debug code |
| `POST` | `/api/code/tests` | Generate tests |

### Projects

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/projects` | List projects |
| `POST` | `/api/projects` | Create project |
| `GET` | `/api/projects/:id` | Get project details |
| `PATCH` | `/api/projects/:id` | Update project |
| `DELETE` | `/api/projects/:id` | Delete project |

### Memory

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/memory` | List memory entries |
| `POST` | `/api/memory` | Create memory entry |
| `PATCH` | `/api/memory/:id` | Update memory entry |
| `DELETE` | `/api/memory/:id` | Delete memory entry |

### RAG Pipeline

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/rag/ingest` | Ingest documents into the vector store |
| `POST` | `/api/rag/query` | Query with RAG-augmented response |
| `POST` | `/api/rag/search` | Raw vector search |
| `POST` | `/api/rag/rerank` | Rerank search results |
| `POST` | `/api/rag/feedback` | Submit relevance feedback |
| `POST` | `/api/rag/reindex` | Trigger reindex |

### Tools

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/tools/browser` | Web browsing tool |
| `POST` | `/api/tools/sql` | SQL query tool |
| `POST` | `/api/tools/vector-search` | Vector search tool |
| `POST` | `/api/tools/external-api` | External API proxy |

### Extensions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/extensions/chrome` | Chrome extension API |
| `POST` | `/api/extensions/excel` | Excel add-in API |
| `POST` | `/api/extensions/powerpoint` | PowerPoint add-in API |

### API Keys

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/keys` | List API keys |
| `POST` | `/api/keys` | Generate new key |
| `POST` | `/api/keys/:id` | Rotate key |
| `DELETE` | `/api/keys/:id` | Delete key |

### Usage and Metrics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/usage` | Usage overview |
| `GET` | `/api/usage/tokens` | Token breakdown by model |
| `GET` | `/api/usage/history` | Historical usage data |
| `GET` | `/api/metrics` | Performance metrics (latency, throughput) |
| `GET` | `/api/health` | Health check |

### Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/admin/users` | List users |
| `PATCH` | `/api/admin/users` | Update user role |
| `GET` | `/api/admin/rag-stats` | RAG index statistics |
| `GET` | `/api/admin/feedback` | Feedback statistics |

### File Upload

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/file/upload` | Upload file |

### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/webhooks/sanity` | Sanity CMS webhook |
| `POST` | `/api/webhooks/segment` | Segment analytics webhook |
| `POST` | `/api/webhooks/intercom` | Intercom webhook |

---

## Design System

The design system is implemented entirely in CSS Custom Properties, with no external CSS framework dependency.

### Theming

Three theme modes supported via `ThemeProvider`:

- **Light**: Clean white backgrounds with subtle shadows
- **Dark**: Deep charcoal backgrounds with soft glows
- **System**: Follows OS preference via `prefers-color-scheme`

Theme is persisted in `localStorage` and applied via `data-theme` attribute on the `<html>` element.

### CSS Variables

```css
/* Backgrounds */
--bg-primary, --bg-secondary, --bg-tertiary

/* Surfaces */
--surface, --surface-hover, --surface-active

/* Text */
--text-primary, --text-secondary, --text-tertiary

/* Accent */
--accent, --accent-light, --accent-hover

/* Borders */
--border, --border-subtle

/* Status */
--success, --warning, --error, --info

/* Shadows */
--shadow-sm, --shadow-md, --shadow-lg, --shadow-glow

/* Radii */
--radius-sm, --radius-md, --radius-lg, --radius-xl

/* Transitions */
--transition-fast, --transition-normal
```

### Icon System

Heroicons 2.x with a consistent style guide:

| Context | Heroicon Style |
|---------|---------------|
| Navigation | Outline (`/24/outline`) |
| Primary Actions | Solid (`/24/solid`) |
| Status Indicators | Solid |
| Disabled / Temp | Outline with reduced opacity |

### Responsive Breakpoints

```css
@media (max-width: 480px)   /* Mobile */
@media (max-width: 768px)   /* Tablet */
@media (max-width: 1024px)  /* Small Desktop */
@media (max-width: 1280px)  /* Desktop */
```

---

## Configuration

### Model Configuration

| Model | ID | Max Tokens | Extended Thinking | Tool Use |
|-------|----|-----------|-------------------|----------|
| Opus 4.6 | `opus-4.6` | 128,000 | Yes | Yes |
| Sonnet 4.6 | `sonnet-4.6` | 64,000 | Yes | Yes |
| Haiku 4.5 | `haiku-4.5` | 32,000 | No | Yes |

### Feature Flags

All features are enabled by default. There is no billing or subscription logic. The `/api/features` endpoint returns all flags as `true`.

---

## Deployment

### Vercel (Recommended)

```bash
npm install -g vercel
vercel
```

Vercel automatically detects Next.js and configures:
- Edge runtime for API routes
- Static generation for applicable pages
- Automatic HTTPS and CDN

### Docker

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
EXPOSE 3000
CMD ["npm", "start"]
```

```bash
docker build -t recall .
docker run -p 3000:3000 recall
```

### Kubernetes

A Helm chart or raw manifests can be used. Minimum recommended resources:

| Component | CPU | Memory | Replicas |
|-----------|-----|--------|----------|
| Web (Next.js) | 500m | 512Mi | 2-4 |
| Worker (BullMQ) | 250m | 256Mi | 2 |
| Redis | 250m | 256Mi | 1 (HA: 3) |
| PostgreSQL | 500m | 1Gi | 1 (HA: 3) |

---

## Security

### Authentication

- JWT-based authentication with RS256 signing
- Refresh token rotation
- Rate limiting per IP and per user

### API Security

- All API routes validate request body schemas
- CORS configured for allowed origins
- CSRF protection via SameSite cookies
- Input sanitization on all user-facing endpoints

### Data Privacy

- Memory can be disabled per-user
- Training data opt-out available
- Data export (GDPR compliance)
- Account deletion with cascade

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

### Development Guidelines

- Use TypeScript strict mode
- Follow the existing CSS variable naming conventions
- Use Heroicons (outline for navigation, solid for actions/status)
- All API routes must use the `jsonResponse` / `errorResponse` helpers
- Write semantic HTML with proper heading hierarchy

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with Next.js, React, TypeScript, and Heroicons</sub>
</p>
