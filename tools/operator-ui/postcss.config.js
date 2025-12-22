import autoprefixer from 'autoprefixer';
import postcss from 'postcss';
import { compile } from 'tailwindcss';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

function walkFiles(dir, out) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(fullPath, out);
      continue;
    }
    if (!entry.isFile()) continue;
    out.push(fullPath);
  }
}

function extractCandidatesFromContent(content) {
  const out = new Set();

  // className="..." and class="..."
  const classRe = /(className|class)\s*=\s*["'`]([^"'`]+)["'`]/g;
  let match;
  while ((match = classRe.exec(content))) {
    for (const token of match[2].split(/\s+/g)) {
      if (token) out.add(token);
    }
  }

  // @apply ...;
  const applyRe = /@apply\s+([^;]+);/g;
  while ((match = applyRe.exec(content))) {
    for (const token of match[1].split(/\s+/g)) {
      if (token) out.add(token);
    }
  }

  return out;
}

function collectCandidates(projectRoot) {
  const srcDir = path.join(projectRoot, 'src');
  const files = [];
  try {
    walkFiles(srcDir, files);
  } catch {
    return [];
  }

  const candidates = new Set();
  for (const file of files) {
    if (!/\.(tsx|ts|jsx|js|css|html)$/.test(file)) continue;
    let content = '';
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    for (const token of extractCandidatesFromContent(content)) {
      candidates.add(token);
    }
  }
  return [...candidates];
}

function tailwindPostcssShim() {
  return {
    postcssPlugin: 'tailwindcss-postcss-shim',
    async Once(root, { result }) {
      const projectRoot = process.cwd();
      const from = result?.opts?.from || root?.source?.input?.file;
      let css = root.toString();
      const base = from ? path.dirname(from) : projectRoot;

      // Vite may pre-process and strip CSS `@import` directives before PostCSS runs.
      // Tailwind v4 relies on importing its layer definitions; if they're missing, core utilities
      // (e.g. `rounded-xl`) become unavailable and `@apply` fails.
      if (!/@import\s+["']tailwindcss["']\s*;/.test(css)) {
        // Keep CSS valid: `@import` must appear before any non-`@charset` statement.
        if (/^\s*@charset\s+["'][^"']+["']\s*;/.test(css)) {
          css = css.replace(
            /^(\s*@charset\s+["'][^"']+["']\s*;)/,
            `$1\n@import "tailwindcss";`,
          );
        } else {
          css = `@import "tailwindcss";\n${css}`;
        }
      }

      if (process.env.MPRD_DEBUG_TAILWIND_SHIM === '1') {
        const head = css.split('\n').slice(0, 10).join('\n');
        console.log('[tailwind-shim]', { from, base, head });
      }

      async function loadModule(id, baseDir, _kind) {
        const resolved = path.resolve(baseDir || base, id);
        const mod = await import(pathToFileURL(resolved).href);
        return {
          module: mod.default ?? mod,
          base: path.dirname(resolved),
        };
      }

      async function loadStylesheet(id, baseDir) {
        let resolved;
        if (id === 'tailwindcss') {
          resolved = path.join(projectRoot, 'node_modules', 'tailwindcss', 'index.css');
        } else if (id.startsWith('tailwindcss/')) {
          // Tailwind package exports several css entrypoints (e.g. `tailwindcss/utilities`).
          const sub = id.slice('tailwindcss/'.length);
          resolved = path.join(projectRoot, 'node_modules', 'tailwindcss', `${sub}.css`);
        } else {
          resolved = path.resolve(baseDir || base, id);
        }
        const content = fs.readFileSync(resolved, 'utf8');
        return {
          content,
          base: path.dirname(resolved),
          path: resolved,
        };
      }

      const compiler = await compile(css, { from, base, loadModule, loadStylesheet });
      const candidates = collectCandidates(projectRoot);
      const built = compiler.build(candidates);
      const parsed = postcss.parse(built, { from });
      root.removeAll();
      root.append(parsed.nodes);
    },
  };
}
tailwindPostcssShim.postcss = true;

export default {
  plugins: [tailwindPostcssShim(), autoprefixer],
};
