// Records the scanner issue-type coverage as a Craft finding, backed by
// evidence from the reference jar: the issue-type enum that names every
// type and the class that writes its text.
//   node qa/craft/record-coverage.mjs "<statement>"
import { withCraft } from './craft.mjs';

const statement = process.argv[2];
if (!statement) throw new Error('usage: record-coverage.mjs "<statement>"');
const jar = process.env.BURP_JAR ?? '/opt/BurpSuite/burpsuite.jar';

await withCraft(async (craft) => {
  await craft.call('core_target_open', { path: jar });
  const shown = await craft.call('java_class_show', { class_name: 'burp.Zcot' });
  const text = JSON.stringify(shown);
  const id = shown?.evidence_id ?? shown?.result?.evidence_id ?? (text.match(/"(ev_[0-9a-f]+)"/) ?? [])[1];
  console.log('evidence', id, text.slice(0, 400));
  if (!id) throw new Error('java_class_show returned no evidence id');
  const rec = await craft.call('core_finding_record', { statement, evidence_ids: [id], confidence: 'derived' });
  console.log('finding', JSON.stringify(rec).slice(0, 300));
}, { deep: true, toolsets: ['java'] });
