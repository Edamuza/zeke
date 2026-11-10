"""Version parsing for vulnerability matching. Every function returns None when unsure (never guesses)."""
import re

_PEP440 = re.compile(
    r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)"
    r"(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?"
    r"(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d*)))?"
    r"(?:[-_.]?(dev)[-_.]?(\d*))?$", re.I)
_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}


def pep440_key(v):
    m = _PEP440.match(str(v).strip().split("+")[0])
    if not m:
        return None
    epoch = int(m.group(1) or 0)
    rel = [int(x) for x in m.group(2).split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    pre = (_PRE[m.group(3).lower()], int(m.group(4) or 0)) if m.group(3) else None
    post = int(m.group(5) or m.group(7) or 0) if (m.group(5) or m.group(6)) else None
    dev = int(m.group(9) or 0) if m.group(8) else None
    # ordering: dev-only release < pre < final < post
    if pre is None and post is None and dev is not None:
        pre_k = (-1, 0)
    elif pre is None:
        pre_k = (9, 0)
    else:
        pre_k = pre
    return (epoch, tuple(rel), pre_k, -1 if post is None else post, 1 << 30 if dev is None else dev)


def gem_key(v):
    s = str(v).strip().lower()
    if not s or not re.match(r"^[0-9]+([.\-a-z0-9])*$", s):
        return None
    toks = [int(t) if t.isdigit() else t for t in re.findall(r"[0-9]+|[a-z]+", s)]
    while len(toks) > 1 and toks[-1] == 0:
        toks.pop()
    return tuple(toks)


def _cmp_gem(a, b):
    n = max(len(a), len(b))
    for i in range(n):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            return -1 if x < y else 1
        return -1 if isinstance(x, str) else 1  # prerelease string < number
    return 0


def compare(eco, a, b):
    """-1/0/1, or None if either side can't be parsed confidently."""
    if eco == "PyPI":
        ka, kb = pep440_key(a), pep440_key(b)
        if ka is None or kb is None:
            return None
        # pad release tuples
        ra, rb = list(ka[1]), list(kb[1])
        n = max(len(ra), len(rb))
        ka = (ka[0], tuple(ra + [0] * (n - len(ra)))) + ka[2:]
        kb = (kb[0], tuple(rb + [0] * (n - len(rb)))) + kb[2:]
        return (ka > kb) - (ka < kb)
    if eco == "RubyGems":
        ka, kb = gem_key(a), gem_key(b)
        if ka is None or kb is None:
            return None
        return _cmp_gem(ka, kb)
    return None


def affected(eco, version, ranges, versions):
    """True / False, or None when it can't be decided."""
    if versions and version in versions:
        return True
    if not ranges:
        return False if versions else None
    for events in ranges:
        state = False
        for ev in events:
            if "introduced" in ev:
                intro = ev["introduced"]
                c = 1 if intro == "0" else compare(eco, version, intro)
                if c is None:
                    return None
                if c >= 0:
                    state = True
            elif "fixed" in ev:
                c = compare(eco, version, ev["fixed"])
                if c is None:
                    return None
                if c >= 0:
                    state = False
            elif "last_affected" in ev:
                c = compare(eco, version, ev["last_affected"])
                if c is None:
                    return None
                if c > 0:
                    state = False
        if state:
            return True
    return False
