'use client';

import { useState, useMemo } from 'react';
import Topbar from '@/components/layout/Topbar';
import {
    MagnifyingGlassIcon,
    BookOpenIcon,
    ChevronDownIcon,
    ChevronRightIcon,
} from '@heroicons/react/24/outline';

/* ------------------------------------------------------------------ */
/*  Documentation Data                                                 */
/* ------------------------------------------------------------------ */

interface DocArticle {
    id: string;
    title: string;
    category: string;
    tags: string[];
    content: string;
}

const docs: DocArticle[] = [
    /* ---- Getting Started ------------------------------------------- */
    {
        id: 'quickstart',
        title: 'Quickstart',
        category: 'Getting Started',
        tags: ['install', 'setup', 'npm', 'node', 'clone', 'run', 'start'],
        content: `Prerequisites: Node.js 18.17+, npm 9+.\n\n1. Clone the repository\n   git clone https://github.com/your-org/recall.git\n   cd recall\n\n2. Install dependencies\n   npm install\n\n3. Start the development server\n   npm run dev\n\nOpen http://localhost:3000 in your browser.\n\nTo create a production build:\n   npm run build\n   npm start`,
    },
    {
        id: 'env-vars',
        title: 'Environment Variables',
        category: 'Getting Started',
        tags: ['environment', 'config', 'env', 'api key', 'database', 'redis', 'pinecone', 'jwt'],
        content: `Create a .env.local file in the project root.\n\nRequired variables:\n- ANTHROPIC_API_KEY: Your Claude API key\n- DATABASE_URL: PostgreSQL connection string\n- REDIS_URL: Redis connection string\n- PINECONE_API_KEY: Pinecone vector DB key\n- PINECONE_INDEX: Name of your Pinecone index\n- JWT_SECRET: Secret for JWT signing (use RS256 in production)\n\nOptional variables:\n- DEFAULT_MODEL: Default AI model (sonnet-4.6)\n- ENABLE_EXTENDED_THINKING: Enable extended thinking (true)\n- ENABLE_TOOL_USE: Enable tool use (true)\n- ENABLE_WEB_SEARCH: Enable web search (true)\n- OTEL_ENDPOINT: OpenTelemetry collector URL\n- LOG_LEVEL: Logging level (info)\n- S3_BUCKET: File upload bucket\n- S3_REGION: AWS region`,
    },
    /* ---- Architecture ---------------------------------------------- */
    {
        id: 'architecture',
        title: 'System Architecture',
        category: 'Architecture',
        tags: ['architecture', 'system', 'design', 'overview', 'diagram', 'flow'],
        content: `Recall follows a modern full-stack architecture built on Next.js App Router.\n\n[Architecture Diagram]\nClient (Browser)\n  -> Next.js App Router\n     -> Frontend Layers (Client Components, ThemeProvider, Layout Shell, Feature Pages)\n     -> Backend Services (Auth, Claude SDK, RAG Pipeline, MCP Client, Code Sandbox, Prisma/DB)\n\nKey architectural pillars:\n- App Router for streaming and SSR\n- Modular Service Architecture in lib/\n- Unified API Envelope for all responses\n- RAG Pipeline with vector retrieval\n- MCP Protocol for tool extensibility`,
    },
    {
        id: 'rag-pipeline',
        title: 'RAG Pipeline',
        category: 'Architecture',
        tags: ['rag', 'retrieval', 'augmented', 'generation', 'vector', 'embedding', 'ingestion', 'pipeline', 'chunking'],
        content: `The RAG pipeline has two main paths:\n\nIngestion Path (offline):\n1. Document Sources (PDFs, web pages, databases)\n2. Ingestion Pipeline (scrapers, ETL, OCR, chunker)\n   - OCR scanned documents, normalize\n   - Chunk (500-1000 tokens), preserve paragraphs\n   - Extract metadata (title, URL, timestamps)\n3. Embedding Service (batch, real-time)\n4. Vector DB / Index Layer (Pinecone, Milvus, FAISS)\n\nQuery Path (online):\n1. User Query -> API Gateway (auth, rate limits)\n2. Request Router (simple Q vs RAG vs agent workflow)\n3. Embedding Service embeds query\n4. Queries Vector DB with metadata filters\n5. Retriever Service fetches top-K results\n6. Reranker rescores with cross-encoder (optional)\n7. Context Builder assembles snippets, citations\n8. Claude Opus 4.6 generates final response\n9. Cache (LRU with TTL) stores response\n10. Return response + sources to user\n\nIndex Types:\n- HNSW: high recall, low latency, good default\n- IVF+PQ: memory efficient for huge corpora\n- DiskANN: disk-backed, scale beyond RAM\n\nScale Recommendations:\n- Small (< 1M vectors): local FAISS\n- Medium (1-10M): managed Pinecone or self-hosted Milvus\n- Large (10M+): Milvus + sharded FAISS + DiskANN`,
    },
    {
        id: 'design-system',
        title: 'Design System',
        category: 'Architecture',
        tags: ['css', 'theme', 'dark', 'light', 'design', 'tokens', 'variables', 'styling'],
        content: `The design system is implemented in CSS Custom Properties.\n\nTheme Modes:\n- Light: clean white backgrounds with subtle shadows\n- Dark: deep charcoal backgrounds with soft glows\n- System: follows OS preference\n\nCSS Variable Categories:\n- Backgrounds: --bg-primary, --bg-secondary, --bg-tertiary\n- Surfaces: --surface, --surface-hover, --surface-active\n- Text: --text-primary, --text-secondary, --text-tertiary\n- Accent: --accent, --accent-light, --accent-hover\n- Borders: --border, --border-subtle\n- Status: --success, --warning, --error, --info\n- Shadows: --shadow-sm, --shadow-md, --shadow-lg, --shadow-glow\n- Radii: --radius-sm, --radius-md, --radius-lg, --radius-xl\n- Transitions: --transition-fast, --transition-normal\n\nResponsive Breakpoints:\n- Mobile: max-width 480px\n- Tablet: max-width 768px\n- Small Desktop: max-width 1024px\n- Desktop: max-width 1280px\n\nIcon System (Heroicons 2.x):\n- Navigation: Outline style\n- Primary Actions: Solid style\n- Status Indicators: Solid style\n- Disabled / Temp: Outline with opacity`,
    },

    /* ---- API Reference --------------------------------------------- */
    {
        id: 'api-chat',
        title: 'Chat API',
        category: 'API Reference',
        tags: ['chat', 'api', 'streaming', 'sse', 'messages', 'conversation', 'send', 'post'],
        content: `POST /api/chat\nStreaming chat completion via Server-Sent Events.\n\nRequest body:\n  conversation_id (string, optional): Existing conversation ID\n  messages (array): Array of message objects\n  model (string): Model ID (default: sonnet-4.6)\n  stream (boolean): Enable SSE streaming (default: true)\n  tools_enabled (boolean): Enable tool use (default: true)\n\nStreaming response (SSE):\n  data: {"type":"text","text":"word "}\n  data: {"type":"done"}\n\nNon-streaming response:\n  { success: true, data: { id, conversation_id, model, content, usage } }\n\nUsage object:\n  input_tokens (number)\n  output_tokens (number)`,
    },
    {
        id: 'api-conversations',
        title: 'Conversations API',
        category: 'API Reference',
        tags: ['conversations', 'api', 'crud', 'list', 'create', 'update', 'delete'],
        content: `GET /api/conversations\nList all conversations. Returns array of conversation objects.\n\nPOST /api/conversations\nCreate a new conversation.\nBody: { title (string), model (string) }\nReturns: 201 with new conversation object.\n\nGET /api/conversations/:id\nGet a specific conversation with messages.\n\nPATCH /api/conversations/:id\nUpdate conversation (title, metadata).\nBody: { title (string) }\n\nDELETE /api/conversations/:id\nDelete a conversation and all its messages.`,
    },
    {
        id: 'api-messages',
        title: 'Messages API',
        category: 'API Reference',
        tags: ['messages', 'api', 'send', 'list', 'conversation'],
        content: `GET /api/messages?conversation_id=xxx\nList messages for a conversation.\n\nPOST /api/messages\nSend a message.\nBody: { conversation_id (string), content (string) }\nReturns: 201 with message object.`,
    },
    {
        id: 'api-models',
        title: 'Models API',
        category: 'API Reference',
        tags: ['models', 'api', 'opus', 'sonnet', 'haiku', 'select', 'list'],
        content: `GET /api/models\nList available models.\n\nReturns array:\n  - opus-4.6: Most capable, 128K tokens, extended thinking, tools\n  - sonnet-4.6: Balanced, 64K tokens, extended thinking, tools\n  - haiku-4.5: Fastest, 32K tokens, tools only\n\nPOST /api/models\nSet default model.\nBody: { model_id (string) }`,
    },
    {
        id: 'api-research',
        title: 'Research API',
        category: 'API Reference',
        tags: ['research', 'api', 'run', 'status', 'report', 'deep', 'multi-source'],
        content: `POST /api/research/run\nStart a research job.\nBody: { topic (string), depth (string: quick|deep|synthesis) }\nReturns: 201 with job object (id, status: running).\n\nGET /api/research/:id\nGet research job status and report.\nReturns: { id, status, topic, sources[], report, completed_at }`,
    },
    {
        id: 'api-code',
        title: 'Code Tools API',
        category: 'API Reference',
        tags: ['code', 'api', 'explain', 'refactor', 'generate', 'run', 'debug', 'tests', 'sandbox'],
        content: `POST /api/code/explain\nExplain code. Body: { code (string), model (string) }\n\nPOST /api/code/refactor\nRefactor code. Body: { code (string) }\n\nPOST /api/code/generate\nGenerate code. Body: { prompt (string), language (string) }\n\nPOST /api/code/run\nExecute code in sandbox. Body: { code (string), language (string) }\nReturns: { output, exit_code }\n\nPOST /api/code/debug\nDebug code. Body: { code (string) }\nReturns: { issues_found, suggestions[] }\n\nPOST /api/code/tests\nGenerate tests. Body: { code (string), framework (string) }\nReturns: { test_count, tests (string) }`,
    },
    {
        id: 'api-rag',
        title: 'RAG Pipeline API',
        category: 'API Reference',
        tags: ['rag', 'api', 'ingest', 'query', 'search', 'rerank', 'feedback', 'reindex', 'vector'],
        content: `POST /api/rag/ingest\nIngest documents into the vector store.\nBody: { documents (array) }\nReturns: 201 with job ID and status.\n\nPOST /api/rag/query\nQuery with RAG-augmented response.\nBody: { query (string), model (string) }\nReturns: { query, results[{ doc_id, content, score, metadata }], total }\n\nPOST /api/rag/search\nRaw vector similarity search.\nBody: { query (string) }\n\nPOST /api/rag/rerank\nRerank search results using cross-encoder.\nBody: { query (string), results (array) }\n\nPOST /api/rag/feedback\nSubmit relevance feedback for a chunk.\nBody: { chunk_id (string), feedback (string) }\n\nPOST /api/rag/reindex\nTrigger a full reindex of the vector store.\nReturns: { status, estimated_time }`,
    },
    {
        id: 'api-projects',
        title: 'Projects API',
        category: 'API Reference',
        tags: ['projects', 'api', 'crud', 'list', 'create', 'update', 'delete', 'files'],
        content: `GET /api/projects\nList all projects.\n\nPOST /api/projects\nCreate a new project.\nBody: { name (string), description (string) }\nReturns: 201 with project object.\n\nGET /api/projects/:id\nGet project details including files, memory, settings.\n\nPATCH /api/projects/:id\nUpdate project metadata.\n\nDELETE /api/projects/:id\nDelete project and associated data.`,
    },
    {
        id: 'api-memory',
        title: 'Memory API',
        category: 'API Reference',
        tags: ['memory', 'api', 'crud', 'preferences', 'context', 'persistent'],
        content: `GET /api/memory\nList all memory entries.\n\nPOST /api/memory\nCreate a memory entry.\nBody: { key (string), value (string), category (string) }\nReturns: 201 with memory object.\n\nPATCH /api/memory/:id\nUpdate a memory entry.\n\nDELETE /api/memory/:id\nDelete a memory entry.`,
    },
    {
        id: 'api-tools',
        title: 'Tools API',
        category: 'API Reference',
        tags: ['tools', 'api', 'browser', 'sql', 'vector', 'external', 'proxy'],
        content: `POST /api/tools/browser\nWeb browsing tool.\nBody: { url (string) }\nReturns: { tool, url, content, status }\n\nPOST /api/tools/sql\nSQL query tool.\nBody: { query (string) }\nReturns: { tool, query, results, rows_affected }\n\nPOST /api/tools/vector-search\nVector search tool.\nBody: { query (string), index (string) }\n\nPOST /api/tools/external-api\nExternal API proxy.\nBody: { endpoint (string), method (string) }`,
    },
    {
        id: 'api-extensions',
        title: 'Extensions API',
        category: 'API Reference',
        tags: ['extensions', 'api', 'chrome', 'excel', 'powerpoint', 'integration'],
        content: `POST /api/extensions/chrome\nChrome extension API.\nBody: { action (string) }\n\nPOST /api/extensions/excel\nExcel add-in API.\nBody: { action (string) }\n\nPOST /api/extensions/powerpoint\nPowerPoint add-in API.\nBody: { action (string) }`,
    },
    {
        id: 'api-keys',
        title: 'API Keys',
        category: 'API Reference',
        tags: ['keys', 'api', 'generate', 'rotate', 'delete', 'authentication'],
        content: `GET /api/keys\nList all API keys (masked).\n\nPOST /api/keys\nGenerate a new API key.\nBody: { name (string) }\nReturns: 201 with full key (shown only once).\n\nPOST /api/keys/:id\nRotate an existing key. Returns new key value.\n\nDELETE /api/keys/:id\nRevoke and delete an API key.`,
    },
    {
        id: 'api-usage',
        title: 'Usage and Metrics API',
        category: 'API Reference',
        tags: ['usage', 'tokens', 'metrics', 'history', 'health', 'latency', 'monitoring'],
        content: `GET /api/usage\nOverall usage metrics.\nReturns: { tokens_used, requests_today, breakdown }\n\nGET /api/usage/tokens\nToken breakdown by model.\nReturns: { input_tokens, output_tokens, model_breakdown }\n\nGET /api/usage/history\nHistorical usage data.\nReturns: { history[{ date, tokens }] }\n\nGET /api/metrics\nPerformance metrics.\nReturns: { latency (p50/p95/p99), requests_per_minute, error_rate, token_throughput }\n\nGET /api/health\nHealth check.\nReturns: { status, uptime, version, services }`,
    },
    {
        id: 'api-admin',
        title: 'Admin API',
        category: 'API Reference',
        tags: ['admin', 'api', 'users', 'rag-stats', 'feedback', 'management'],
        content: `GET /api/admin/users\nList all users with roles and status.\n\nPATCH /api/admin/users\nUpdate user role.\nBody: { id (string), role (string) }\n\nGET /api/admin/rag-stats\nRAG index statistics.\nReturns: { total_documents, total_chunks, index_size_mb, last_reindex }\n\nGET /api/admin/feedback\nFeedback statistics.\nReturns: { positive, negative, neutral, satisfaction_rate }`,
    },
    {
        id: 'api-features',
        title: 'Features API',
        category: 'API Reference',
        tags: ['features', 'api', 'flags', 'billing', 'free', 'unlocked'],
        content: `GET /api/features\nList all feature flags. All features are enabled by default.\nThere is no billing or subscription logic.\n\nReturns all flags as true:\nchat_basic, chat_extended_output, claude_code, cowork_mode, memory,\nresearch_access, unlimited_projects, excel_extension, chrome_extension,\npowerpoint_extension, early_access, priority_queue, extended_thinking,\ntool_use, file_upload, image_input, api_access, mcp_connectors,\nslack_integration, google_workspace, vscode_extension`,
    },

    /* ---- Feature Guides -------------------------------------------- */
    {
        id: 'guide-chat',
        title: 'Chat',
        category: 'Feature Guides',
        tags: ['chat', 'conversation', 'message', 'streaming', 'model', 'extended thinking', 'send'],
        content: `The Chat page (/chat) provides a full-featured chat interface.\n\nConversation List (left sidebar):\n- Click "+ New Chat" to start a new conversation\n- Click a conversation to switch to it\n- Shows title, date, and message preview\n\nModel Selector:\n- Click the model name in the top bar to change models\n- Opus 4.6: most capable for ambitious work\n- Sonnet 4.6: balanced for everyday tasks\n- Haiku 4.5: fastest for quick answers\n- Toggle Extended Thinking for complex reasoning\n\nChat Input:\n- Type your message and press Enter to send\n- Shift+Enter for a new line\n- Attach files with the PaperClip icon\n- Upload images with the Photo icon\n\nMessage Actions:\n- Copy: copy AI response to clipboard\n- Regenerate: regenerate the last response`,
    },
    {
        id: 'guide-research',
        title: 'Research',
        category: 'Feature Guides',
        tags: ['research', 'deep', 'multi-source', 'synthesis', 'sources', 'report', 'export'],
        content: `The Research page (/research) provides a multi-step AI research agent.\n\nStarting Research:\n1. Enter a research topic in the input field\n2. Select depth: Quick (30s), Deep (2-5m), or Multi-Source (5-15m)\n3. Click "Start Research"\n\nDuring Research:\n- A progress indicator shows the agent is working\n- Sources are discovered and analyzed in real-time\n\nResults:\n- Sources are listed with relevance scores (0-100%)\n- A structured research report is generated\n- Export as PDF or save to a project\n- Copy the report to clipboard\n\nPrevious Research:\n- Past research jobs are listed with topic, source count, and status`,
    },
    {
        id: 'guide-code',
        title: 'Code',
        category: 'Feature Guides',
        tags: ['code', 'editor', 'file tree', 'ai', 'explain', 'refactor', 'debug', 'tests', 'run'],
        content: `The Code page (/code) provides a three-panel code environment.\n\nFile Tree (left):\n- Navigate your project files and folders\n- Click a file to open it in the editor\n- Click "+" to create a new file\n\nEditor (center):\n- Syntax-highlighted code display\n- Tab-based file navigation\n\nAI Assistant (right):\n- Contextual analysis of the active file\n- Quick actions:\n  - Explain: get a plain-English explanation\n  - Refactor: suggest improvements\n  - Tests: generate test cases\n  - Debug: find and fix issues\n  - Run: execute code in a sandbox\n- Ask custom questions about the code`,
    },
    {
        id: 'guide-projects',
        title: 'Projects',
        category: 'Feature Guides',
        tags: ['projects', 'create', 'manage', 'files', 'organize', 'search'],
        content: `The Projects page (/projects) provides project management.\n\nCreating Projects:\n1. Click "+ New Project"\n2. Enter project name and description\n3. Click "Create"\n\nProject Cards:\n- Color-coded project cards in a grid layout\n- Shows name, description, file count, last updated\n- Upload files with the upload icon\n- Access project settings with the gear icon\n\nSearch:\n- Use the search bar to filter projects by name\n- Search icon is embedded in the input field`,
    },
    {
        id: 'guide-memory',
        title: 'Memory',
        category: 'Feature Guides',
        tags: ['memory', 'preferences', 'context', 'persistent', 'edit', 'delete', 'search'],
        content: `The Memory page (/memory) manages persistent AI memory.\n\nRecall remembers your preferences, context, and working style across conversations.\n\nCategories:\n- Preferences: language, framework, code style choices\n- Context: current project, active work\n- Infrastructure: deployment, hosting decisions\n- Profile: background, expertise areas\n\nManaging Memory:\n- Add Memory: click "+ Add Memory", enter key and value\n- Edit: click the pencil icon on any entry\n- Delete: click the trash icon\n- Search: use the search bar to filter by key or value\n\nMemory can be disabled in Settings > Data & Privacy.`,
    },
    {
        id: 'guide-extensions',
        title: 'Extensions',
        category: 'Feature Guides',
        tags: ['extensions', 'chrome', 'excel', 'powerpoint', 'slack', 'vscode', 'mcp', 'google', 'api'],
        content: `The Extensions page (/extensions) is the extension marketplace.\n\nAvailable Extensions:\n- Chrome Extension: AI in your browser, highlight text to analyze\n- Excel Add-in: formulas, visualizations, data insights\n- PowerPoint Add-in: generate presentations, speaker notes\n- API Access: REST API with streaming and tool use\n- Slack Integration: AI responses in Slack channels\n- VS Code Extension: code completion and debugging\n- MCP Connectors: Model Context Protocol for custom tools\n- Google Workspace: Gmail, Docs, Sheets, Drive integration\n\nAll extensions are included for free.\n\nStatus:\n- Green check: connected and active\n- Gray dot: not yet connected\n- Click Configure or Install to manage`,
    },
    {
        id: 'guide-settings',
        title: 'Settings',
        category: 'Feature Guides',
        tags: ['settings', 'profile', 'theme', 'api keys', 'privacy', 'model', 'appearance'],
        content: `The Settings page (/settings) has five tabs.\n\nProfile:\n- Update name, email, and avatar\n- Click "Save Changes" to persist\n\nModels:\n- Select default model (Opus, Sonnet, Haiku)\n- Toggle Extended Thinking on/off\n- Toggle Tool Use on/off\n- Adjust max output tokens (1K-128K)\n\nAppearance:\n- Choose theme: Light, Dark, or System\n- Visual theme cards with live preview\n\nAPI Keys:\n- View existing keys (masked)\n- Generate new keys\n- Rotate or delete existing keys\n\nData & Privacy:\n- Toggle cross-conversation memory\n- Opt out of training data usage\n- Danger Zone: export data, delete all data, delete account`,
    },
    {
        id: 'guide-admin',
        title: 'Admin Dashboard',
        category: 'Feature Guides',
        tags: ['admin', 'dashboard', 'users', 'health', 'metrics', 'stats', 'management'],
        content: `The Admin page (/admin) provides system oversight.\n\nStats Cards:\n- Active Users: current count with weekly trend\n- Messages Today: daily message volume\n- Avg Latency: API response time\n- Token Usage: total tokens consumed\n\nUser Management:\n- Table of users with name, email, role, status, last seen\n- Edit roles (Admin, User)\n- Active/inactive status with icons\n\nSystem Health:\n- Per-service status: API Gateway, Vector DB, Redis Cache, Worker Queue, AI Inference\n- Uptime percentage\n- Reindex action for each service\n- Operational (green) vs Degraded (yellow) indicators`,
    },

    /* ---- Deployment ------------------------------------------------ */
    {
        id: 'deploy-vercel',
        title: 'Deploy to Vercel',
        category: 'Deployment',
        tags: ['deploy', 'vercel', 'production', 'hosting', 'edge', 'cdn'],
        content: `Vercel is the recommended deployment platform.\n\n1. Install Vercel CLI:\n   npm install -g vercel\n\n2. Deploy:\n   vercel\n\nVercel automatically:\n- Detects Next.js and configures build\n- Enables Edge runtime for API routes\n- Static generation for applicable pages\n- Automatic HTTPS and CDN\n- Preview deployments for pull requests\n\nEnvironment variables can be set in:\nVercel Dashboard > Project > Settings > Environment Variables`,
    },
    {
        id: 'deploy-docker',
        title: 'Deploy with Docker',
        category: 'Deployment',
        tags: ['deploy', 'docker', 'container', 'image', 'build', 'run'],
        content: `Dockerfile (multi-stage build):\n\nFROM node:20-alpine AS builder\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci\nCOPY . .\nRUN npm run build\n\nFROM node:20-alpine AS runner\nWORKDIR /app\nCOPY --from=builder /app/.next ./.next\nCOPY --from=builder /app/node_modules ./node_modules\nCOPY --from=builder /app/package.json ./\nEXPOSE 3000\nCMD ["npm", "start"]\n\nBuild and run:\n  docker build -t recall .\n  docker run -p 3000:3000 --env-file .env.local recall`,
    },
    {
        id: 'deploy-kubernetes',
        title: 'Deploy to Kubernetes',
        category: 'Deployment',
        tags: ['deploy', 'kubernetes', 'k8s', 'helm', 'pods', 'scaling', 'orchestration'],
        content: `Minimum recommended resources:\n\nComponent       CPU    Memory   Replicas\nWeb (Next.js)   500m   512Mi    2-4\nWorker (BullMQ) 250m   256Mi    2\nRedis           250m   256Mi    1 (HA: 3)\nPostgreSQL      500m   1Gi      1 (HA: 3)\n\nKey considerations:\n- Use Horizontal Pod Autoscaler (HPA) for the web tier\n- Redis Sentinel or Cluster for high availability\n- PostgreSQL with streaming replication\n- Ingress with TLS termination\n- PodDisruptionBudgets for zero-downtime deployments`,
    },

    /* ---- Security -------------------------------------------------- */
    {
        id: 'security',
        title: 'Security',
        category: 'Security',
        tags: ['security', 'auth', 'jwt', 'cors', 'csrf', 'rate limiting', 'encryption', 'privacy'],
        content: `Authentication:\n- JWT-based with RS256 signing\n- Refresh token rotation\n- Rate limiting per IP and per user\n\nAPI Security:\n- Schema validation on all request bodies\n- CORS configured for allowed origins\n- CSRF protection via SameSite cookies\n- Input sanitization on all endpoints\n\nData Privacy:\n- Memory can be disabled per-user\n- Training data opt-out\n- Data export (GDPR compliance)\n- Account deletion with cascade\n\nInfrastructure:\n- HTTPS everywhere (TLS 1.3)\n- Secrets in environment variables (never committed)\n- Dependency scanning with npm audit\n- Container image scanning in CI/CD`,
    },
];

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function DocsPage() {
    const [search, setSearch] = useState('');
    const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
    const [selectedCategory, setSelectedCategory] = useState<string | null>(null);

    const categories = useMemo(
        () => [...new Set(docs.map((d) => d.category))],
        [],
    );

    const filteredDocs = useMemo(() => {
        let results = docs;

        if (selectedCategory) {
            results = results.filter((d) => d.category === selectedCategory);
        }

        if (search.trim()) {
            const q = search.toLowerCase();
            results = results.filter(
                (d) =>
                    d.title.toLowerCase().includes(q) ||
                    d.content.toLowerCase().includes(q) ||
                    d.tags.some((t) => t.includes(q)) ||
                    d.category.toLowerCase().includes(q),
            );
        }

        return results;
    }, [search, selectedCategory]);

    const toggleExpand = (id: string) => {
        setExpandedIds((prev) => {
            const next = new Set(prev);
            next.has(id) ? next.delete(id) : next.add(id);
            return next;
        });
    };

    const expandAll = () => setExpandedIds(new Set(filteredDocs.map((d) => d.id)));
    const collapseAll = () => setExpandedIds(new Set());

    const highlightMatch = (text: string) => {
        if (!search.trim()) return text;
        const regex = new RegExp(`(${search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
        return text.replace(regex, '||$1||');
    };

    return (
        <>
            <Topbar title="Documentation" />
            <div className="page-content">
                <div className="page" style={{ maxWidth: '960px' }}>
                    <div className="page-header" style={{ textAlign: 'center', marginBottom: '32px' }}>
                        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '12px' }}>
                            <BookOpenIcon style={{ width: 36, height: 36, color: 'var(--accent)' }} />
                        </div>
                        <h1 className="page-title">Documentation</h1>
                        <p className="page-subtitle">
                            Search and browse the complete Recall platform documentation.
                        </p>
                    </div>

                    {/* Search bar */}
                    <div style={{ position: 'relative', marginBottom: '24px' }}>
                        <MagnifyingGlassIcon
                            style={{
                                width: 20,
                                height: 20,
                                position: 'absolute',
                                left: '16px',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                color: 'var(--text-tertiary)',
                            }}
                        />
                        <input
                            type="text"
                            className="input input-lg"
                            placeholder="Search docs... (e.g. streaming, RAG, deploy, theme)"
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            style={{ paddingLeft: '44px', fontSize: '15px' }}
                            id="docs-search"
                        />
                        {search && (
                            <span
                                style={{
                                    position: 'absolute',
                                    right: '16px',
                                    top: '50%',
                                    transform: 'translateY(-50%)',
                                    fontSize: '13px',
                                    color: 'var(--text-tertiary)',
                                }}
                            >
                                {filteredDocs.length} result{filteredDocs.length !== 1 ? 's' : ''}
                            </span>
                        )}
                    </div>

                    {/* Category pills + expand/collapse */}
                    <div
                        style={{
                            display: 'flex',
                            gap: '8px',
                            flexWrap: 'wrap',
                            marginBottom: '24px',
                            alignItems: 'center',
                        }}
                    >
                        <button
                            className={`home-action-chip ${!selectedCategory ? 'selected' : ''}`}
                            onClick={() => setSelectedCategory(null)}
                            style={{ fontSize: '13px' }}
                        >
                            All
                        </button>
                        {categories.map((cat) => (
                            <button
                                key={cat}
                                className={`home-action-chip ${selectedCategory === cat ? 'selected' : ''}`}
                                onClick={() => setSelectedCategory(selectedCategory === cat ? null : cat)}
                                style={{ fontSize: '13px' }}
                            >
                                {cat}
                            </button>
                        ))}
                        <div style={{ flex: 1 }} />
                        <button className="btn btn-sm btn-ghost" onClick={expandAll}>
                            Expand all
                        </button>
                        <button className="btn btn-sm btn-ghost" onClick={collapseAll}>
                            Collapse all
                        </button>
                    </div>

                    {/* Articles */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {filteredDocs.length === 0 && (
                            <div
                                style={{
                                    textAlign: 'center',
                                    padding: '48px 0',
                                    color: 'var(--text-tertiary)',
                                    fontSize: '15px',
                                }}
                            >
                                No documentation matches your search.
                            </div>
                        )}

                        {filteredDocs.map((doc) => {
                            const isOpen = expandedIds.has(doc.id);
                            return (
                                <div key={doc.id} className="card" style={{ padding: 0, overflow: 'hidden' }}>
                                    <button
                                        onClick={() => toggleExpand(doc.id)}
                                        style={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: '12px',
                                            width: '100%',
                                            padding: '14px 20px',
                                            background: 'transparent',
                                            border: 'none',
                                            cursor: 'pointer',
                                            color: 'var(--text-primary)',
                                            textAlign: 'left',
                                            fontSize: '14px',
                                        }}
                                    >
                                        {isOpen ? (
                                            <ChevronDownIcon style={{ width: 16, height: 16, flexShrink: 0, color: 'var(--accent)' }} />
                                        ) : (
                                            <ChevronRightIcon style={{ width: 16, height: 16, flexShrink: 0, color: 'var(--text-tertiary)' }} />
                                        )}
                                        <span style={{ fontWeight: 600, flex: 1 }}>{doc.title}</span>
                                        <span
                                            className="badge badge-info"
                                            style={{ fontSize: '11px', fontWeight: 500 }}
                                        >
                                            {doc.category}
                                        </span>
                                    </button>

                                    {isOpen && (
                                        <div
                                            style={{
                                                padding: '0 20px 16px 48px',
                                                whiteSpace: 'pre-wrap',
                                                fontFamily: 'var(--font-mono, monospace)',
                                                fontSize: '13px',
                                                lineHeight: 1.7,
                                                color: 'var(--text-secondary)',
                                            }}
                                        >
                                            {highlightMatch(doc.content)
                                                .split('||')
                                                .map((part, i) =>
                                                    i % 2 === 1 ? (
                                                        <mark
                                                            key={i}
                                                            style={{
                                                                background: 'var(--accent-light, #e6d8ff)',
                                                                color: 'var(--text-primary)',
                                                                borderRadius: '2px',
                                                                padding: '0 2px',
                                                            }}
                                                        >
                                                            {part}
                                                        </mark>
                                                    ) : (
                                                        <span key={i}>{part}</span>
                                                    ),
                                                )}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                </div>
            </div>
        </>
    );
}
