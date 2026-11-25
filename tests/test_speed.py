"""Speed fixes for long text: same results as the simple code, without square-time loops."""
import random
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pii_sanitizer as ps  # noqa: E402


def naive_resolve(findings):
    ranked = sorted(findings, key=ps._overlap_rank)
    taken, keep = [], []
    for f in ranked:
        if f.length <= 0 or any(f.start < e and s < f.end for s, e in taken):
            continue
        taken.append((f.start, f.end))
        keep.append(f)
    return sorted(keep, key=lambda f: f.start)


def random_findings(rng, n, text_len=2000):
    out = []
    for _ in range(n):
        s = rng.randrange(text_len)
        e = min(text_len, s + rng.randrange(0, 40))
        out.append(ps.Finding(s, e, "x" * (e - s), rng.choice(["PERSON", "LOCATION", "IP_ADDRESS"]),
                              rng.choice([0.5, 0.85, 0.9, 1.0]),
                              rng.choice(["presidio", "custom", "propagated", "hebrew_ner", "manual"]),
                              rng.choice(["", "SpacyRecognizer", "rule"])))
    return out


class CoverageTests(unittest.TestCase):
    def test_coverage_union_and_queries(self):
        c = ps._Coverage([(10, 20), (15, 30), (40, 50)])
        self.assertEqual(list(zip(c.starts, c.ends)), [(10, 30), (40, 50)])
        self.assertTrue(c.overlaps(29, 35))
        self.assertFalse(c.overlaps(30, 40), "touching is not overlapping")
        self.assertEqual(c.within(0, 45), [(10, 30), (40, 45)])
        c.add(30, 40)
        self.assertEqual(list(zip(c.starts, c.ends)), [(10, 50)])

    def test_resolve_overlaps_matches_simple_version(self):
        rng = random.Random(7)
        for _ in range(200):
            fs = random_findings(rng, rng.randrange(1, 80))
            self.assertEqual(ps.resolve_overlaps(fs), naive_resolve(fs))

    def test_uncovered_pieces_same_with_coverage_object(self):
        rng = random.Random(11)
        text = "".join(rng.choice("אבג abc-' ") for _ in range(500))
        for _ in range(200):
            spans = [(s, s + rng.randrange(1, 30)) for s in (rng.randrange(480) for _ in range(rng.randrange(0, 15)))]
            a = rng.randrange(450)
            b = a + rng.randrange(1, 50)
            self.assertEqual(ps._uncovered_pieces(text, a, b, ps._Coverage(spans)),
                             ps._uncovered_pieces(text, a, b, spans))


class FastContextEnhancerTests(unittest.TestCase):
    def test_token_index_matches_presidio(self):
        from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer
        rng = random.Random(3)
        words = ["John", "Smith", "logged", "into", "SRV-DC01", "from", "10.20.30.40", ",", "ok", "."]
        tokens, idx, pos = [], [], 0
        for _ in range(300):
            w = rng.choice(words)
            tokens.append(w)
            idx.append(pos)
            pos += len(w) + rng.choice([0, 1, 1, 2])
        fast = ps.FastContextEnhancer()
        for start in range(0, pos):
            try:
                want = LemmaContextAwareEnhancer._find_index_of_match_token("w", start, tokens, idx)
            except ValueError:
                with self.assertRaises(ValueError):
                    fast._find_index_of_match_token("w", start, tokens, idx)
                continue
            self.assertEqual(fast._find_index_of_match_token("w", start, tokens, idx), want, start)


class QtIndexTests(unittest.TestCase):
    def slow(self, text, idx):
        return idx + sum(1 for c in text[:idx] if ord(c) > 0xFFFF)

    def test_same_as_simple_count(self):
        rng = random.Random(5)
        alphabet = "ab שלום \n" + "\U0001F600\U0001F4A9"
        for _ in range(50):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 300)))
            for idx in range(len(text) + 1):
                self.assertEqual(ps.py_to_qt_index(text, idx), self.slow(text, idx))

    def test_new_text_is_not_mixed_with_cached_text(self):
        a = "\U0001F600" * 5 + "x"
        b = "y" * 6
        self.assertEqual(ps.py_to_qt_index(a, 5), 10)
        self.assertEqual(ps.py_to_qt_index(b, 5), 5)
        self.assertEqual(ps.py_to_qt_index(a, 6), 11)


if __name__ == "__main__":
    unittest.main()
