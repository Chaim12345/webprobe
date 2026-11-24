// Records a finding about the scanner's issue types in Craft, backed by
// evidence from the reference jar: its issue-type enum burp.Zcot.
//   node qa/craft/record-coverage.mjs "<statement>"
//
// The jar must be the build the decompiled sources come from. The class
// names of /opt/BurpSuite/burpsuite.jar are different: its burp.Zcot is
// not the issue enum.
import { withCraft } from './craft.mjs';

const statement = process.argv[2];
if (!statement) throw new Error('usage: record-coverage.mjs "<statement>"');
const jar = process.env.BURP_JAR ?? '/root/burp-re/in/burpsuite.jar';

await withCraft(async (craft) => {
  await craft.call('core_target_open', { path: jar });
  const shown = await craft.call('java_class_show', { class_name: 'burp.Zcot' });
  const text = JSON.stringify(shown);
  if (!/extends java\.lang\.Enum/.test(text)) throw new Error(`burp.Zcot in ${jar} is not the issue-type enum: wrong build`);
  const id = shown?.evidence_id ?? shown?.result?.evidence_id ?? (text.match(/"(ev_[0-9a-f]+)"/) ?? [])[1];
  console.log('evidence', id, text.slice(0, 400));
  if (!id) throw new Error('java_class_show returned no evidence id');
  const rec = await craft.call('core_finding_record', { statement, evidence_ids: [id], confidence: 'derived' });
  console.log('finding', JSON.stringify(rec).slice(0, 300));
}, { deep: true, toolsets: ['java'] });
