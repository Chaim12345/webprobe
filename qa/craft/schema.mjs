import { withCraft } from './craft.mjs';
// Prints a tool's input schema: node schema.mjs <tool> [toolset...]
const [tool, ...toolsets] = process.argv.slice(2);
await withCraft(async (craft) => {
  for (const id of toolsets) await craft.call('enable_toolset', { toolset: id });
  const all = await craft.schemas();
  const hit = all.filter((t) => !tool || t.name === tool);
  console.log(JSON.stringify(hit.map((t) => ({ name: t.name, input: t.inputSchema?.properties, required: t.inputSchema?.required })), null, 1));
});
