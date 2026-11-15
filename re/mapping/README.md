# Deobfuscation map — build 52685

`burpsuite.jar` is ZKM-obfuscated: class names are regenerated **per build**, so a map
recovered from another build only partially applies. Everything in this directory is
therefore tied to one build and says which build it was measured on.

```
/opt/BurpSuite/burpsuite.jar
sha256 510bf1c87c766f09c3c20d3ef75e7a6978e60dd38346965dd4836ce64417becf   (build 52685)
```

## Files

| file | what it is | evidence |
|---|---|---|
| `classMap.tsv` | hand-verified names for the classes this project actually models | runtime + bytecode + shipped docs |
| `methodMap.tsv` | method renames, keyed by the **obfuscated** owner | bytecode |
| `build52685.tsv` | every class in this build that implements a Montoya public-API type | `javap` hierarchy of this jar |
| `string-evidence.tsv` | decoded strings per class (what each class really decrypts) | `RuntimeStringDump` on this jar |
| `coverage.tsv` | the older structural pass checked against this build | name match against the jar |
| `hierarchy52685.tsv` (generated) | class / superclass / interfaces for 17 637 classes of this build | `javap -p` |

## Why the old map is not enough

`/root/burp-re/out/runtime_names/complete_class_map.tsv` holds 12 754 names. Checked against
this jar (`coverage.tsv`):

```
entries in the old map      12 754
present in build 52685       4 690
stale (name not in jar)      8 064
```

So two thirds of that map does not apply to this build. It is kept for reference only; a name
is only usable when the key exists in this jar **and** something in this jar evidences it.

## Naming rules (in order of trust)

1. **Montoya anchor** — the class implements an interface from `burp.api.montoya.**`
   (`build52685.tsv`, 301 classes). The interface *is* the contract, so the name is
   `Montoya<Interface>`. This is the strongest evidence available without a debug symbol table.
2. **Decoded string** — `RuntimeStringDump.java` finds the `a(int,int)` call sites with ASM and
   then calls Burp's own decryptor, so the strings in `string-evidence.tsv` are what the class
   really decrypts at run time (41 662 strings across 4 669 classes; 61 classes carry readable,
   distinctive ones). Names derived from these are quoted with the string they came from.
3. **Hierarchy** — `extends javax.swing.*` / `java.awt.*` (628 classes) says "this is a UI
   component of that kind", which is a role, not a name.
4. **Call-site shape** — last resort; recorded as a role with the rule stated, never as if it
   were an original name.

## Rebuilding

```bash
# 1. hierarchy + interface anchors for THIS jar
unzip -Z1 /opt/BurpSuite/burpsuite.jar 'burp/*.class' | sed 's#/#.#g; s#\.class$##' \
  | grep -v '\$' | sort -u > /tmp/classes.txt
xargs -a /tmp/classes.txt -n 200 javap -p -cp /opt/BurpSuite/burpsuite.jar > /tmp/raw.txt

# 2. runtime-decoded strings
java -cp asm.jar:asm-commons.jar:. RuntimeStringDump /opt/BurpSuite/burpsuite.jar

# 3. apply a map to a copy of the jar (never to the original)
java -cp asm.jar:asm-commons.jar:. JarRemapper \
  /opt/BurpSuite/burpsuite.jar /tmp/named/burpsuite-named.jar \
  re/mapping/classMap.tsv re/mapping/methodMap.tsv
```

## Rules for extending the map

- Key on the **obfuscated** owner (`Zfhv`, not `HotkeyRegistry`): after remapping, the owner no
  longer exists under the old name.
- Rename an interface method in the interface **and in every implementor**
  (`Zt92` → `Zmcg`, `Zfhe`).
- If one class has two methods with the same obfuscated name (an instance method and a static),
  leave the name alone — a method map cannot tell them apart.
- Add one line per rename with the evidence in the fourth column, and record the finding in the
  craft investigation (`core_finding_record`) so the claim is auditable.