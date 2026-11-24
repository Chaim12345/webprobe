// Calls one Craft tool with JSON arguments and prints the result.
//   node qa/craft/call.mjs <tool> ['{"json":"args"}' | @file.json] [--deep] [--toolset=<id>]...
import fs from 'node:fs';
import { withCraft } from './craft.mjs';

const [tool, raw, ...flags] = process.argv.slice(2);
if (!tool) throw new Error('usage: call.mjs <tool> [json | @file] [--deep] [--toolset=<id>]');
const text = !raw || raw.startsWith('--') ? '{}' : raw.startsWith('@') ? fs.readFileSync(raw.slice(1), 'utf8') : raw;
const all = raw?.startsWith('--') ? [raw, ...flags] : flags;
const toolsets = all.filter((f) => f.startsWith('--toolset=')).map((f) => f.slice('--toolset='.length));
await withCraft(async (craft) => {
  console.log(JSON.stringify(await craft.call(tool, JSON.parse(text)), null, 1));
}, { deep: all.includes('--deep'), toolsets });
