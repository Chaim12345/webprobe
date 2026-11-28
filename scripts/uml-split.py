#!/usr/bin/env python3
"""Split one Mermaid class diagram into small ones and print them as Markdown.

Mermaid lays unrelated classes out in a single row, so a directory with dozens
of types becomes one very wide, unreadable picture. This groups classes that
are linked to each other and packs the groups into diagrams of at most
MAX_CLASSES classes. It also rewrites parentheses in field types: Mermaid
reads them as a method signature and then fails to draw the class.

Usage: uml-split.py DIAGRAM.mmd
"""
import re
import sys

MAX_CLASSES = 9
REL = re.compile(r"^\s*(\w+)\s+(?:<\|--|--\|>|\*--|--\*|o--|--o|-->|<--|\.\.>|<\.\.|\.\.\|>|<\|\.\.|--|\.\.)\s+(\w+)")


def parse(text):
    classes, relations, cur = {}, [], None
    for line in text.splitlines():
        if cur is None:
            m = re.match(r"\s*class (\w+)\s*\{", line)
            if m:
                cur = m.group(1)
                classes[cur] = [line]
            elif re.match(r"\s*class (\w+)\s*$", line):
                classes[line.split()[1]] = [line]
            elif REL.match(line):
                relations.append((REL.match(line).group(1), REL.match(line).group(2), line))
        else:
            if re.match(r"\s*[+\-#~]\w+: ", line):
                line = line.replace("(", "[").replace(")", "]")
            classes[cur].append(line)
            if line.strip() == "}":
                cur = None
    return classes, relations


def groups(classes, relations):
    parent = {c: c for c in classes}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b, _ in relations:
        if a in parent and b in parent:
            parent[find(a)] = find(b)
    comps = {}
    for c in classes:  # insertion order keeps source order
        comps.setdefault(find(c), []).append(c)
    linked = [g for g in comps.values() if len(g) > 1]
    single = [g[0] for g in comps.values() if len(g) == 1]
    out = []
    for g in linked:  # a large linked group is cut, losing only cross-part links
        out += [g[i:i + MAX_CLASSES] for i in range(0, len(g), MAX_CLASSES)]
    out += [single[i:i + MAX_CLASSES] for i in range(0, len(single), MAX_CLASSES)]
    return out


def main():
    classes, relations = parse(open(sys.argv[1]).read())
    parts = groups(classes, relations)
    for n, names in enumerate(parts, 1):
        inside = set(names)
        if len(parts) > 1:
            print(f"## Part {n} of {len(parts)}: {', '.join(names[:4])}{' ...' if len(names) > 4 else ''}\n")
        print("```mermaid\nclassDiagram\n    direction LR")
        for name in names:
            print("\n".join(classes[name]))
        for a, b, line in relations:
            if a in inside and b in inside:
                print(line)
        print("```\n")


if __name__ == "__main__":
    main()
