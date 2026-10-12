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


if __name__ == "__main__":
    unittest.main()
