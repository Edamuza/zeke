"""Run from the repo root:  /usr/bin/python3 -m unittest discover -s tests -v"""
import os
import sys
import tempfile
import unittest

os.environ["ZEKE_DATA_DIR"] = tempfile.mkdtemp()   # never touch real data
os.environ.setdefault("ZEKE_HOME", tempfile.mkdtemp())
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import engine  # noqa: E402
from checks import versions, is_urgent, rank  # noqa: E402


class Compare(unittest.TestCase):
    def test_padding(self):
        self.assertEqual(engine.compare("2.5", "2.5.1"), "outdated")
        self.assertEqual(engine.compare_app("4.1", "4.1.2,123")[0], "outdated")
        self.assertEqual(engine.compare("6.6.10.70120", "6.6.10"), "current")
        self.assertEqual(engine.compare("2.5.1", "2.5.1"), "current")

    def test_app_rules(self):
        self.assertEqual(engine.compare_app("157.1.99.55", "1.99.55")[0], "current")
        self.assertEqual(engine.compare_app("1.2.5", "2.0.0")[0], "unknown")
        self.assertEqual(engine.compare_app("1.3.0", "3.0")[0], "unknown")
        self.assertEqual(engine.compare_app("0.0.0", "0.21.2")[0], "unknown")
        self.assertEqual(engine.compare_app("3.24.9", "3.29.15")[0], "outdated")


class Versions(unittest.TestCase):
    def test_gem(self):
        self.assertEqual(versions.compare("RubyGems", "1.0.0.rc1", "1.0.0"), -1)
        self.assertEqual(versions.compare("RubyGems", "3.2.4", "3.2.10"), -1)
        self.assertEqual(versions.compare("RubyGems", "1.0", "1.0.0"), 0)

    def test_pypi(self):
        self.assertEqual(versions.compare("PyPI", "1.0a1", "1.0"), -1)
        self.assertEqual(versions.compare("PyPI", "1.0.post1", "1.0"), 1)
        self.assertEqual(versions.compare("PyPI", "1.0.dev1", "1.0a1"), -1)
        self.assertIsNone(versions.compare("PyPI", "not-a-version!", "1.0"))

    def test_affected(self):
        r = [[{"introduced": "0"}, {"fixed": "3.3.9"}]]
        self.assertTrue(versions.affected("RubyGems", "3.2.4", r, []))
        self.assertFalse(versions.affected("RubyGems", "3.3.9", r, []))
        r2 = [[{"introduced": "1.0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"last_affected": "2.1"}]]
        self.assertTrue(versions.affected("PyPI", "2.1", r2, []))
        self.assertFalse(versions.affected("PyPI", "1.5", r2, []))
        self.assertFalse(versions.affected("PyPI", "2.2", r2, []))
        self.assertIsNone(versions.affected("PyPI", "weird!!", r, []))


class Urgency(unittest.TestCase):
    def f(self, **kw):
        d = dict(state="open", kind="vuln", severity="high", fix={"type": "update"}, exploited=False)
        d.update(kw)
        return d

    def test_rules(self):
        self.assertTrue(is_urgent(self.f(exploited=True)))
        self.assertFalse(is_urgent(self.f(exploited=True, state="muted")))
        self.assertTrue(is_urgent(self.f(severity="critical")))
        self.assertFalse(is_urgent(self.f(severity="high")))
        self.assertTrue(is_urgent(self.f(kind="posture", severity="high", fix={"type": "open"})))
        self.assertLess(rank(self.f(exploited=True)), rank(self.f(severity="medium")))


class Plan(unittest.TestCase):
    def test_holds_and_security_first(self):
        inv = {"items": [
            engine.item("gem:rexml", "rexml", "Ruby gems", "3.2.4", "3.3.9", "outdated", "update", "", True),
            engine.item("gem:rake", "rake", "Ruby gems", "13.0", "13.1", "outdated", "update", "", True),
            engine.item("brew:formula:pg", "pg", "Homebrew formulae", "17.5", "17.6", "outdated", "update", "", True),
            engine.item("brew:formula:x", "x", "Homebrew formulae", "1.0", "2.0", "outdated", "update", "", True, major=True),
            engine.item("pip:mlx", "mlx", "Python packages", "1", "2", "outdated", "update", "", False),
        ]}
        sec = {"findings": [{"item_id": "gem:rexml", "state": "open", "fix": {"type": "update"}}]}
        engine.checks._write(engine.paths.HOLDS, {"brew:formula:pg": {"mode": "hold"}})
        pl = engine.plan(inv, sec)
        self.assertEqual(pl["security_first"], ["gem:rexml"])
        self.assertIn("brew:formula:pg", pl["held"])
        self.assertNotIn("pip:mlx", pl["others"])
        self.assertIn("brew:formula:x", pl["majors"])
        steps = engine.plan_steps(pl)
        self.assertIn("security", steps[0][0])
        self.assertEqual(steps[0][1][-1], "rexml")
        self.assertFalse(any("pg" in s[1] for s in steps))
        os.remove(engine.paths.HOLDS)

    def test_unsafe_names_refused(self):
        bad = engine.item("gem:;rm -rf ~", "x", "Ruby gems", "1", "2", "outdated", "update", "", True)
        self.assertIsNone(engine.action_for(bad))


if __name__ == "__main__":
    unittest.main()
