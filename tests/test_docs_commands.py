"""Every `python tools/<x>.py` or `bash tools/<x>.sh` mentioned in AGENTS.md, README, skills and the task-pack templates must exist."""
import glob
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = re.compile(r"(?:python3?|bash)\s+(tools/[\w./-]+)")


class DocsCommands(unittest.TestCase):
    def test_mentioned_tool_scripts_exist(self):
        files = [os.path.join(ROOT, "AGENTS.md"), os.path.join(ROOT, "README.md")]
        files += glob.glob(os.path.join(ROOT, ".claude", "skills", "*", "SKILL.md"))
        files += glob.glob(os.path.join(ROOT, "templates", "**", "*.md"), recursive=True)
        bad = []
        for f in files:
            with open(f, encoding="utf-8") as fh:
                for m in SCRIPT.findall(fh.read()):
                    if not os.path.exists(os.path.join(ROOT, m.rstrip(".,)"))):
                        bad.append((os.path.relpath(f, ROOT), m))
        self.assertEqual(bad, [])

    def test_rw_options_mentioned_for_rebuild_exist(self):
        src = open(os.path.join(ROOT, "tools", "rebuild_analysis.py"), encoding="utf-8").read()
        for flag in ("--dry-run", "--local-file", "--accept-new-hash", "--max-heap", "--url", "--force", "--recover"):
            self.assertIn('"%s"' % flag, src, flag)

    def test_skill_frontmatter(self):
        for f in glob.glob(os.path.join(ROOT, ".claude", "skills", "*", "SKILL.md")):
            folder = os.path.basename(os.path.dirname(f))
            lines = open(f, encoding="utf-8").read().splitlines()
            self.assertEqual(lines[0], "---", folder)
            head = lines[1:lines.index("---", 1)]
            meta = dict(l.split(": ", 1) for l in head)
            self.assertEqual(meta.get("name"), folder)
            self.assertTrue(0 < len(meta.get("description", "")) <= 1024, folder)
            # reWork RE skills stay under 120 lines; the imported dbug-* framework
            # skills are longer by design, so they get a higher cap.
            cap = 200 if folder.startswith("dbug-") else 120
            self.assertLess(len(lines), cap, folder)

    def test_skill_paths_exist(self):
        rx = re.compile(r"(\.claude/skills/[\w./-]+\.(?:py|md))")
        bad = []
        for f in glob.glob(os.path.join(ROOT, ".claude", "skills", "*", "SKILL.md")) + [os.path.join(ROOT, "README.md")]:
            for m in rx.findall(open(f, encoding="utf-8").read()):
                if not os.path.exists(os.path.join(ROOT, m)):
                    bad.append((os.path.relpath(f, ROOT), m))
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
