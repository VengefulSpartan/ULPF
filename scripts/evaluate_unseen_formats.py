"""
Score the parser on log formats it has no vendor pack for (tests/unseen_corpus.py).

WRONG  = a field filled with a value that differs from the truth. Must be 0: a SIEM trusts these.
MISSED = a field left empty. Acceptable: the event says it is unverified, and a parser learned
         from samples in Parser Studio fills it later.

Part 2 (--learned) measures what a learned parser adds: for three formats with many lines
(tests/format_samples.py), a parser is learned from 150 lines, a reviewer accepts its
proposals, and 100 new lines are scored with the generic parser and with the learned one.

    python scripts/evaluate_unseen_formats.py [--json] [--learned]
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.services.normalization.ocsf_normalizer import OCSFNormalizer  # noqa: E402
from backend.services.parsing.dispatch import parse_log  # noqa: E402
from tests.unseen_corpus import CORPUS, score  # noqa: E402


def evaluate():
    rows = []
    for case in CORPUS:
        fmt, parsed = parse_log(case["line"])
        ev = OCSFNormalizer.normalize(parsed, case["line"], "r", "h", vendor=parsed.get("vendor") or "Generic",
                                      product=parsed.get("product") or "Device").model_dump()
        wrong, missed, correct = score(ev, case["truth"])
        conf = ((ev.get("unmapped") or {}).get("tracelog_parse") or {}).get("confidence")
        rows.append({"format": case["name"], "parser": fmt, "wrong": wrong, "missed": missed, "correct": correct,
                     "confidence": conf})
    return rows


def evaluate_learned():
    from backend.services.parser_generation.learned import CompiledSpec
    from backend.services.parser_generation.learner import apply_edits, learn, pending_review
    from backend.services.parsing.inference import fingerprint, infer, structure
    from backend.services.vendors.envelope import split_envelope
    from tests.format_samples import lines, ssh_auth, vpc_flow, watchguard

    def ocsf(parsed, line):
        return OCSFNormalizer.normalize(parsed, line, "r", "h", vendor=parsed.get("vendor") or "Generic",
                                        product=parsed.get("product") or "Device").model_dump()

    rows = []
    for name, gen in (("WatchGuard Firebox", watchguard), ("AWS VPC flow log", vpc_flow), ("OpenSSH logins", ssh_auth)):
        result = learn(lines(gen(150, seed=1)))
        spec, val = result["spec"], result["validation"]
        reviewed = [s["label"] for s in pending_review(spec)]
        apply_edits(spec, confirmed=[s["id"] for s in pending_review(spec)], reviewer="evaluation")
        compiled = CompiledSpec(spec, "eval", name)
        totals = {"generic": [0, 0, 0], "learned": [0, 0, 0]}
        for case in gen(100, seed=99):
            env = split_envelope(case["line"])
            st = structure(env.message)
            _, generic = infer(case["line"], env, st)
            hit, _ = compiled.apply(case["line"], env, st, fingerprint(st, env))
            for key, parsed in (("generic", generic), ("learned", hit[1] if hit else generic)):
                wrong, missed, correct = score(ocsf(parsed, case["line"]), case["truth"])
                totals[key][0] += len(correct)
                totals[key][1] += len(missed)
                totals[key][2] += len(wrong)
        rows.append({"format": name, "held_out_passed": f"{val['passed_samples']}/{val['total_samples']}",
                     "confirmed_by_reviewer": reviewed, **{k: dict(zip(("correct", "missed", "wrong"), v))
                                                         for k, v in totals.items()}})
    return rows


def main():
    rows = evaluate()
    if "--json" in sys.argv:
        out = {"generic": rows}
        if "--learned" in sys.argv:
            out["learned"] = evaluate_learned()
        print(json.dumps(out, indent=2))
        return
    tw = sum(len(r["wrong"]) for r in rows)
    tm = sum(len(r["missed"]) for r in rows)
    tc = sum(len(r["correct"]) for r in rows)
    print(f"{'format':48} {'parser':22} {'correct':>7} {'missed':>6} {'wrong':>5}")
    for r in rows:
        print(f"{r['format'][:48]:48} {r['parser'][:22]:22} {len(r['correct']):7} {len(r['missed']):6} "
              f"{len(r['wrong']):5}")
        for w in r["wrong"]:
            print(f"{'':50}WRONG {w}")
    print(f"\ntotal: {tc} correct, {tm} missed, {tw} WRONG out of {tc + tm + tw} fields in {len(rows)} formats")
    if "--learned" in sys.argv:
        print(f"\n{'learned from 150 lines, scored on 100 new':40} {'generic c/m/w':>15} {'learned c/m/w':>15}  "
              f"confirmed by the reviewer")
        for r in evaluate_learned():
            g, l = r["generic"], r["learned"]
            print(f"{r['format']:40} {g['correct']:>5}/{g['missed']}/{g['wrong']:<5} {l['correct']:>7}/{l['missed']}/"
                  f"{l['wrong']:<5}  {', '.join(r['confirmed_by_reviewer']) or '-'}")


if __name__ == "__main__":
    main()
