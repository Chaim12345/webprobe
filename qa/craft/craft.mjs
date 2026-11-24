// Scripted access to the Craft Anything MCP server for this investigation,
// through mcporter's runtime: one server process, many tool calls.
//
//   import { withCraft } from './craft.mjs';
//   await withCraft(async (craft) => { console.log(await craft.call('core_session_show')); });
//
// MCPORTER_HOME overrides where the mcporter package is looked up.
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
// The investigation lives in the main checkout. From a linked worktree,
// go through git's common directory so every worktree shares one memory.
const commonDir = execFileSync('git', ['-C', here, 'rev-parse', '--path-format=absolute', '--git-common-dir'], { encoding: 'utf8' }).trim();
export const repoRoot = path.dirname(commonDir);
export const project = path.join(repoRoot, 'investigation.cany');

async function loadMcporter() {
  const root = process.env.MCPORTER_HOME
    ?? path.join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'mcporter');
  return import(pathToFileURL(path.join(root, 'dist', 'index.js')).href);
}

function parse(result) {
  const text = (result?.content ?? []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
  if (result?.structuredContent) return result.structuredContent;
  try { return JSON.parse(text); } catch { return text; }
}

/** Runs `fn` with a connected client; `deep` lets tools read inside a target. */
export async function withCraft(fn, { deep = false, toolsets = [] } = {}) {
  const { createRuntime } = await loadMcporter();
  const args = ['mcp', '--project', project];
  if (deep) args.unshift('--deep');
  const runtime = await createRuntime({
    servers: [{ name: 'craft', command: { kind: 'stdio', command: '/usr/bin/craft-anything-cli', args, cwd: repoRoot } }],
  });
  const craft = {
    tools: async () => (await runtime.listTools('craft')).map((t) => t.name),
    schemas: () => runtime.listTools('craft', { includeSchema: true }),
    raw: (tool, params = {}) => runtime.callTool('craft', tool, { args: params }),
    call: async (tool, params = {}) => {
      const result = await runtime.callTool('craft', tool, { args: params });
      const value = parse(result);
      if (result?.isError) throw new Error(`${tool}: ${typeof value === 'string' ? value : JSON.stringify(value)}`.slice(0, 600));
      return value;
    },
  };
  try {
    for (const name of toolsets) await craft.call('enable_toolset', { toolset: name });
    return await fn(craft);
  } finally {
    await runtime.close();
  }
}
