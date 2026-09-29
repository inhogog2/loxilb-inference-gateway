#!/usr/bin/env python3
"""Generate the per-construct Jinja parity goldens (kv_jinja_construct_parity.json).

The gateway's in-process template executor (pkg/loxinet/ai_kv_jinja.go)
implements a subset of Jinja. Whole-template goldens
(gen_chat_render_fixtures.py) prove a model's template renders
byte-identically, but they only reach the constructs a plain chat happens to
execute. This oracle pins every construct the executor supports, one row
each, including its edge semantics (Undefined propagation, Python str()/repr
casing, JSON spacing, macro scoping, loop controls) and the cases that must
raise.

Each row is rendered through transformers' OWN chat-template environment
(_compile_jinja_template: ImmutableSandboxedEnvironment, trim_blocks,
lstrip_blocks, loopcontrols, the tojson override, raise_exception,
strftime_now) — the environment engines call apply_chat_template through —
so run this inside the engine image whose renderer the gateway must match.

strftime_now is frozen to KV_JINJA_FROZEN_NOW so date-bearing rows are
reproducible; the Go test injects the same instant.

Usage:
  gen_jinja_construct_fixtures.py <out.json>
"""
import datetime as _dt
import json
import sys

KV_JINJA_FROZEN_NOW = _dt.datetime(2026, 3, 5, 7, 8, 9)

MSGS = [
    {"role": "system", "content": "sys"},
    {"role": "user", "content": "hi"},
    {"role": "assistant", "content": "<think>\nr\n</think>\n\nans"},
    {"role": "user", "content": "bye"},
]

# (name, template, context). Context values are JSON-shaped: str, int, bool,
# None, list, dict (insertion-ordered). Rows whose render raises are recorded
# as errors; the executor must refuse them too.
CASES = [
    # --- literals and output casing -------------------------------------
    ("lit-none", "{{ none }}|{{ None }}", {}),
    ("lit-bools", "{{ true }}{{ false }}{{ True }}", {}),
    ("lit-int", "{{ 42 }}{{ -3 }}", {}),
    ("lit-str-escapes", r"""{{ 'a\nb\tc\\d\'e"f' }}""", {}),
    ("lit-str-dq-escapes", r'''{{ "x\"yéz" }}''', {}),
    ("lit-str-unknown-escape", r"""{{ 'p\qr' }}""", {}),
    ("lit-str-adjacent", "{{ 'a' 'b' }}", {}),
    ("lit-list-out", "{{ [1, 'a', none, true] }}", {}),
    ("lit-tuple-out", "{{ (1, 'a') }}", {}),
    ("lit-dict-out", "{{ {'b': 1, 'a': 'x'} }}", {}),
    ("lit-list-len", "{{ [1, 2, 3]|length }}", {}),
    ("lit-dict-index", "{% set d = {'user': 'U', 'assistant': 'A'} %}{{ d['user'] }}{{ d.assistant }}", {}),
    ("lit-dict-multiline", "{%- set d = {\n    'user': '[u]\\n',\n    'x': 1\n} %}{{ d['user'] }}", {}),
    ("lit-list-trailing-comma", "{{ [1, 2,]|length }}", {}),
    ("lit-empty-tuple", "{{ ()|length }}", {}),
    ("lit-paren-not-tuple", "{{ (1) + 1 }}", {}),
    # --- arithmetic ------------------------------------------------------
    ("arith-mod", "{{ 7 % 3 }}{{ -7 % 3 }}{{ 7 % -3 }}", {}),
    ("arith-mul", "{{ 3 * 4 }}", {}),
    ("arith-floordiv", "{{ 7 // 2 }}{{ -7 // 2 }}", {}),
    ("arith-str-mul", "{{ 'ab' * 3 }}", {}),
    ("arith-precedence", "{{ 1 + 2 * 3 }}|{{ 10 - 4 % 3 }}", {}),
    ("arith-list-add", "{{ ([1] + [2, 3])|length }}", {}),
    ("arith-mod-zero", "{{ 1 % 0 }}", {}),
    ("arith-div-float", "{{ 7 / 2 }}", {}),
    ("arith-str-plus-int", "{{ 'a' + 1 }}", {}),
    ("concat-tilde-types", "{{ 'a' ~ 1 ~ none ~ true ~ undef }}", {}),
    ("concat-tilde-list", "{{ 'a' ~ [1, 'b'] }}", {}),
    ("concat-tilde-dict", "{{ 'a' ~ {'k': 'v', 'n': 1} }}", {}),
    ("concat-plus-undef", "{{ 'a' + undef }}", {}),
    # --- comparisons / membership ----------------------------------------
    ("cmp-int-bool", "{{ 1 == true }}|{{ 0 == false }}|{{ 2 == true }}", {}),
    ("cmp-paren-compare-compare", "{{ (1 == 1) != (2 == 3) }}|{{ ('user' == 'user') != (3 % 2 == 0) }}", {}),
    ("cmp-chained", "{{ 1 < 2 < 3 }}", {}),
    ("cmp-str-order", "{{ 'a' < 'b' }}", {}),
    ("cmp-list-eq", "{{ [1, 2] == [1, 2] }}", {}),
    ("cmp-none", "{{ none == none }}|{{ none != 0 }}", {}),
    ("cmp-undef", "{{ undef == none }}|{{ undef != 1 }}", {}),
    ("in-mapping", "{{ 'role' in m }}|{{ 'tools' in m }}|{{ 'tools' not in m }}", {"m": {"role": "user", "content": "x"}}),
    ("in-list", "{{ 2 in [1, 2] }}|{{ 'z' in ['a'] }}", {}),
    ("in-string", "{{ 'ell' in 'hello' }}", {}),
    ("in-dict-literal", "{% set r = {'user': 1} %}{{ 'user' in r }}{{ 'tool' not in r }}", {}),
    ("in-undef", "{{ 'a' in undef }}", {}),
    ("in-none", "{{ 'a' in none }}", {}),
    # --- conditional expression ------------------------------------------
    ("condexpr-basic", "{{ 'y' if true else 'n' }}{{ 'y' if 0 else 'n' }}", {}),
    ("condexpr-no-else", "[{{ 'y' if false }}]", {}),
    ("condexpr-nested", "{{ 'a' if x == 1 else 'b' if x == 2 else 'c' }}", {"x": 2}),
    ("condexpr-precedence", "{{ 'p' + ('q' if true else 'r') }}|{{ 'p' + 'q' if false else 'r' }}", {}),
    ("condexpr-filter", "{{ v | string if v is string else v | tojson }}", {"v": {"a": 1}}),
    # --- attribute / subscript semantics ----------------------------------
    ("attr-missing-key", "[{{ m.nope }}]|{{ m.nope is defined }}", {"m": {"a": 1}}),
    ("attr-on-none", "[{{ n.x }}]|{{ n.x is defined }}", {"n": None}),
    ("attr-on-str", "{{ s.x is defined }}", {"s": "abc"}),
    ("attr-on-list", "{{ l.x is defined }}", {"l": [1]}),
    ("attr-on-undef", "{{ undef.x }}", {}),
    ("index-out-of-range", "[{{ l[5] }}]|{{ l[5] is defined }}", {"l": [1, 2]}),
    ("index-negative", "{{ l[-1] }}", {"l": [1, 2]}),
    ("index-str", "{{ s[0] }}{{ s[-1] }}", {"s": "héllo"}),
    ("index-undef", "{{ undef[0] }}", {}),
    ("index-int-on-dict", "[{{ d[0] }}]", {"d": {"a": 1}}),
    ("slice-str", "{{ s[1:] }}|{{ s[:2] }}|{{ s[::-1] }}|{{ s[9:] }}", {"s": "<think>héllo"}),
    ("slice-list", "{{ l[1:]|length }}{{ l[::-1][0] }}", {"l": [1, 2, 3]}),
    # --- tests -------------------------------------------------------------
    ("test-iterable", "{{ 'a' is iterable }}{{ [1] is iterable }}{{ {'a':1} is iterable }}{{ none is iterable }}{{ 1 is iterable }}{{ undef is iterable }}", {}),
    ("test-mapping", "{{ {'a':1} is mapping }}{{ [1] is mapping }}{{ 'a' is mapping }}{{ none is mapping }}{{ undef is mapping }}", {}),
    ("test-sequence", "{{ 'a' is sequence }}{{ [1] is sequence }}{{ {'a':1} is sequence }}{{ none is sequence }}{{ 1 is sequence }}{{ undef is sequence }}", {}),
    ("test-boolean", "{{ true is boolean }}{{ 1 is boolean }}{{ none is boolean }}", {}),
    ("test-string", "{{ 'a' is string }}{{ 1 is string }}{{ undef is string }}", {}),
    ("test-number-integer", "{{ 1 is number }}{{ 'a' is number }}{{ 1 is integer }}{{ true is number }}", {}),
    ("test-none", "{{ none is none }}{{ undef is none }}{{ 0 is none }}", {}),
    ("test-true-false", "{{ true is true }}{{ 1 is true }}{{ false is false }}{{ 0 is false }}", {}),
    ("test-defined-undefined", "{{ x is defined }}{{ x is undefined }}{{ y is defined }}", {"x": None}),
    ("test-not", "{{ 'a' is not string }}{{ none is not none }}", {}),
    ("test-divisibleby", "{{ 4 is divisibleby(2) }}{{ 5 is divisibleby 2 }}", {}),
    ("test-eq", "{{ 1 is eq 1 }}{{ 'a' is equalto 'b' }}", {}),
    ("test-in", "{{ 1 is in [1, 2] }}", {}),
    ("test-odd-even", "{{ 3 is odd }}{{ 3 is even }}", {}),
    ("test-callable", "{% macro m() %}{% endmacro %}{{ m is callable }}", {}),
    # --- filters -----------------------------------------------------------
    ("filter-default", "{{ undef | default('d') }}|{{ none | default('d') }}|{{ '' | default('d') }}|{{ '' | default('d', true) }}|{{ none | default('d', true) }}|{{ 0 | d('z', true) }}", {}),
    ("filter-default-list", "{{ (undef | default([])) | length }}", {}),
    ("filter-default-kw", "{{ '' | default('d', boolean=true) }}", {}),
    ("filter-safe", "{{ '<a>' | safe }}", {}),
    ("filter-string", "{{ 1 | string }}{{ none | string }}{{ true | string }}{{ [1,'a'] | string }}{{ undef | string }}|", {}),
    ("filter-items", "{% for k, v in d | items %}{{ k }}={{ v }};{% endfor %}", {"d": {"b": 1, "a": 2, "c": 3}}),
    ("filter-items-undef", "{% for k, v in undef | items %}{{ k }}{% endfor %}|", {}),
    ("filter-items-none", "{% for k, v in n | items %}{{ k }}{% endfor %}|", {"n": None}),
    ("filter-dictsort", "{% for k, v in d | dictsort %}{{ k }}={{ v }};{% endfor %}", {"d": {"b": 1, "A": 2, "a": 3}}),
    ("filter-join", "{{ ['a', 'b', 'c'] | join(', ') }}|{{ [1, 2] | join }}|{{ [] | join('x') }}", {}),
    ("filter-join-attr", "{{ l | join('|', attribute='n') }}", {"l": [{"n": "a"}, {"n": "b"}]}),
    ("filter-list", "{{ 'abc' | list | length }}{{ (d | list)[0] }}", {"d": {"k1": 1, "k2": 2}}),
    ("filter-map-filter", "{{ ['a', 'b'] | map('upper') | join(',') }}", {}),
    ("filter-map-attr", "{{ l | map(attribute='n') | join(',') }}", {"l": [{"n": "a"}, {"n": "b"}]}),
    ("filter-replace", "{{ 'aXbXc' | replace('X', '-') }}|{{ 'aXbXc' | replace('X', '-', 1) }}", {}),
    ("filter-upper-lower", "{{ 'aB' | upper }}{{ 'aB' | lower }}", {}),
    ("filter-trim", "[{{ '  a b \n' | trim }}]", {}),
    ("filter-trim-chars", "[{{ 'xxaxx' | trim('x') }}]", {}),
    ("filter-length-count", "{{ 'héllo' | length }}{{ [1,2] | count }}{{ {'a':1} | length }}", {}),
    ("filter-length-undef", "{{ undef | length }}", {}),
    ("filter-first-last", "{{ [1,2,3] | first }}{{ [1,2,3] | last }}", {}),
    ("filter-capitalize-title", "{{ 'hello world' | capitalize }}|{{ 'hello world' | title }}", {}),
    ("filter-int", "{{ '42' | int + 1 }}", {}),
    ("filter-unknown", "{{ 'a' | frobnicate }}", {}),
    # tojson: transformers overrides Jinja's filter with json.dumps(ensure_ascii=False)
    ("tojson-str", "{{ s | tojson }}", {"s": "a\"b\\c\n\t<>&'é \x01"}),
    ("tojson-dict", "{{ d | tojson }}", {"d": {"name": "f", "args": {"x": 1, "y": [1, "a", None, True]}}}),
    ("tojson-indent", "{{ d | tojson(indent=4) }}", {"d": {"a": [1, {"b": 2}], "c": {}}}),
    ("tojson-indent-2", "{{ d | tojson(indent=2) }}", {"d": {"a": [], "b": "x"}}),
    ("tojson-ensure-ascii", "{{ s | tojson(ensure_ascii=True) }}|{{ s | tojson(ensure_ascii=False) }}", {"s": "é안"}),
    ("tojson-sort-keys", "{{ d | tojson(sort_keys=true) }}", {"d": {"b": 1, "a": 2}}),
    ("tojson-separators", "{{ d | tojson(separators=(',', ':')) }}", {"d": {"a": [1, 2]}}),
    ("tojson-none-undef", "{{ none | tojson }}", {}),
    ("tojson-undef", "{{ undef | tojson }}", {}),
    # --- methods -------------------------------------------------------------
    ("method-dict-get", "{{ d.get('a') }}|{{ d.get('z') }}|{{ d.get('z', 'dflt') }}", {"d": {"a": 1}}),
    ("method-dict-items", "{% for k, v in d.items() %}{{ k }}{{ v }}{% endfor %}", {"d": {"z": 1, "y": 2}}),
    ("method-dict-keys-values", "{{ d.keys() | list | join(',') }}|{{ d.values() | list | length }}", {"d": {"z": 1, "y": 2}}),
    ("method-str-split-noarg", "{{ ' a  b '.split() | length }}", {}),
    ("method-str-split-max", "{{ 'a,b,c'.split(',', 1)[1] }}", {}),
    ("method-str-strip-chars", "[{{ '\\n\\nx\\n'.lstrip('\\n') }}]", {}),
    ("method-str-replace", "{{ 'aab'.replace('a', 'x') }}", {}),
    ("method-str-startswith-tuple", "{{ 'abc'.startswith(('x', 'a')) }}", {}),
    ("method-str-upper-title", "{{ 'ab cd'.upper() }}{{ 'ab cd'.title() }}", {}),
    ("method-str-find", "{{ 'abc'.find('c') }}", {}),
    ("method-str-format", "{{ '{}-{}'.format(1, 'a') }}", {}),
    ("method-unknown-on-dict", "{{ d.frob() }}", {"d": {}}),
    ("method-on-undef", "{{ undef.split('a') }}", {}),
    # --- for loops -----------------------------------------------------------
    ("for-loop-vars", "{% for x in l %}{{ loop.index }}{{ loop.index0 }}{{ loop.revindex }}{{ loop.revindex0 }}{{ loop.first }}{{ loop.last }}{{ loop.length }};{% endfor %}", {"l": ["a", "b"]}),
    ("for-previtem-nextitem", "{% for x in l %}[{{ loop.previtem }}|{{ loop.nextitem }}|{{ loop.previtem is defined }}]{% endfor %}", {"l": ["a", "b", "c"]}),
    ("for-previtem-attr", "{% for m in msgs %}{% if loop.previtem and loop.previtem.role != 'user' %}P{% endif %}{% if not loop.last and loop.nextitem.role != 'user' %}N{% endif %}{% endfor %}", {"msgs": MSGS}),
    ("for-unpack", "{% for a, b in [[1, 2], [3, 4]] %}{{ a }}{{ b }}{% endfor %}", {}),
    ("for-unpack-arity", "{% for a, b in [[1, 2, 3]] %}{{ a }}{% endfor %}", {}),
    ("for-over-dict", "{% for k in d %}{{ k }}{% endfor %}", {"d": {"b": 1, "a": 2}}),
    ("for-over-string", "{% for c in 'héy' %}{{ c }}.{% endfor %}", {}),
    ("for-over-undef", "[{% for x in undef %}{{ x }}{% endfor %}]", {}),
    ("for-over-none", "[{% for x in n %}{{ x }}{% endfor %}]", {"n": None}),
    ("for-else", "{% for x in [] %}{{ x }}{% else %}empty{% endfor %}", {}),
    ("for-else-nonempty", "{% for x in [1] %}{{ x }}{% else %}empty{% endfor %}", {}),
    ("for-if-filter", "{% for x in [1, 2, 3, 4] if x % 2 == 0 %}{{ x }}{{ loop.index }}{% endfor %}", {}),
    ("for-continue", "{% for x in [1, 2, 3] %}{% if x == 2 %}{% continue %}{% endif %}{{ x }}{% endfor %}", {}),
    ("for-break", "{% for x in [1, 2, 3] %}{% if x == 2 %}{% break %}{% endif %}{{ x }}{% endfor %}", {}),
    ("for-continue-ws", "{%- for x in [1, 2] %}\n  {%- if x == 1 %}\n    {{- 'a' -}}\n    {%- continue %}\n  {%- endif %}\n  {{- 'b' }}\n{% endfor %}\nZ", {}),
    ("for-range", "{% for i in range(3) %}{{ i }}{% endfor %}|{% for i in range(1, 4) %}{{ i }}{% endfor %}|{% for i in range(5, 0, -2) %}{{ i }}{% endfor %}", {}),
    ("for-range-len", "{% for i in range(msgs | length) %}{{ msgs[i].role[0] }}{% endfor %}", {"msgs": MSGS}),
    ("for-scope-no-leak", "{% set x = 'out' %}{% for i in [1] %}{% set x = 'in' %}{% endfor %}{{ x }}", {}),
    ("for-loop-var-shadow-restore", "{% set m = 'top' %}{% for m in [1] %}{% endfor %}{{ m }}", {}),
    ("for-nested-loop", "{% for a in [1, 2] %}{% for b in [3] %}{{ loop.index }}{% endfor %}{{ loop.index }}{% endfor %}", {}),
    ("for-namespace-carry", "{% set ns = namespace(n=0) %}{% for x in [1, 2, 3] %}{% set ns.n = ns.n + x %}{% endfor %}{{ ns.n }}", {}),
    ("for-reversed-slice", "{% for m in msgs[::-1] %}{{ loop.index0 }}{{ m.role[0] }}{% endfor %}", {"msgs": MSGS}),
    # --- set ------------------------------------------------------------------
    ("set-block", "{% set x %}a{{ 1 }}b{% endset %}[{{ x }}]", {}),
    ("set-block-trim", "{%- set x -%}\n  body\n{%- endset -%}\n[{{ x }}]", {}),
    ("set-block-in-if", "{% if true %}{% set x %}v{% endset %}{% endif %}{{ x }}", {}),
    ("set-tuple", "{% set a, b = 1, 2 %}{{ a }}{{ b }}", {}),
    ("set-in-if-visible", "{% if true %}{% set y = 5 %}{% endif %}{{ y }}", {}),
    ("set-shadow-context", "{% set messages = messages[1:] %}{{ messages | length }}", {"messages": MSGS}),
    # --- macros -----------------------------------------------------------------
    ("macro-basic", "{% macro f(a, b) %}[{{ a }}-{{ b }}]{% endmacro %}{{ f(1, 'x') }}", {}),
    ("macro-default-arg", "{% macro f(a, b='d', c=none) %}{{ a }}{{ b }}{{ c }}{% endmacro %}{{ f(1) }}|{{ f(1, c=3) }}", {}),
    ("macro-missing-arg", "{% macro f(a, b) %}[{{ a }}|{{ b }}|{{ b is defined }}]{% endmacro %}{{ f(1) }}", {}),
    ("macro-extra-arg", "{% macro f(a) %}{{ a }}{% endmacro %}{{ f(1, 2) }}", {}),
    ("macro-unknown-kwarg", "{% macro f(a) %}{{ a }}{% endmacro %}{{ f(a=1, z=2) }}", {}),
    ("macro-ws", "{%- macro f(x) %}\n    {{- 'v' ~ x }}\n{%- endmacro %}\n{{- f(1) }}|{{ f(2) }}", {}),
    ("macro-returns-string-filter", "{% macro f() %}  pad  {% endmacro %}[{{ f() | trim }}]", {}),
    ("macro-in-set", "{% macro f(c) %}{{ c }}!{% endmacro %}{% set r = f('x') | trim %}{{ r }}{{ r | length }}", {}),
    ("macro-sees-context", "{% macro f() %}{{ messages | length }}{% endmacro %}{{ f() }}", {"messages": MSGS}),
    ("macro-sees-top-set-before", "{% set g = 'G' %}{% macro f() %}{{ g }}{% endmacro %}{{ f() }}", {}),
    ("macro-sees-top-set-after", "{% macro f() %}[{{ g }}]{% endmacro %}{% set g = 'G' %}{{ f() }}", {}),
    ("macro-no-caller-loop-var", "{% macro f() %}[{{ item }}]{% endmacro %}{% for item in [1] %}{{ f() }}{% endfor %}", {}),
    ("macro-namespace-mutation", "{% set ns = namespace(c=0) %}{% macro f() %}{% set ns.c = ns.c + 1 %}{% endmacro %}{{ f() }}{{ f() }}{{ ns.c }}", {}),
    ("macro-set-local", "{% set x = 'top' %}{% macro f() %}{% set x = 'mac' %}{{ x }}{% endmacro %}{{ f() }}{{ x }}", {}),
    ("macro-recursive", "{% macro f(n) %}{{ n }}{% if n > 0 %}{{ f(n - 1) }}{% endif %}{% endmacro %}{{ f(3) }}", {}),
    ("macro-calls-macro", "{% macro g(x) %}<{{ x }}>{% endmacro %}{% macro f(x) %}{{ g(x) }}{% endmacro %}{{ f('a') }}", {}),
    ("macro-raise", "{% macro f() %}{{ raise_exception('boom') }}{% endmacro %}{{ f() }}", {}),
    ("macro-param-shadows-global", "{% macro f(messages) %}{{ messages }}{% endmacro %}{{ f('p') }}", {"messages": MSGS}),
    ("macro-bool-default", "{% macro f(c, v=false, s=true) %}{{ v }}{{ s }}{% endmacro %}{{ f(1, true) }}", {}),
    ("macro-undefined-call", "{{ nosuch(1) }}", {}),
    # --- raise / globals ----------------------------------------------------------
    ("raise-exception", "a{{ raise_exception('bad role') }}b", {}),
    ("raise-exception-untaken", "{% if false %}{{ raise_exception('x') }}{% endif %}ok", {}),
    ("strftime-now", "{{ strftime_now('%d %b %Y') }}|{{ strftime_now('%Y-%m-%d') }}|{{ strftime_now('%B %A %a %H:%M:%S %y %j %p %I %e') }}", {}),
    ("strftime-defined", "{{ strftime_now is defined }}", {}),
    ("namespace-kw", "{% set ns = namespace(a=1, b='x') %}{{ ns.a }}{{ ns.b }}{{ ns.c is defined }}", {}),
    ("namespace-dict-arg", "{% set ns = namespace({'a': 1}) %}{{ ns.a }}", {}),
    ("range-defined", "{{ range(2) | list | length }}", {}),
    ("dict-builtin", "{{ dict(a=1)['a'] }}", {}),
    ("cycler-refused", "{{ cycler(1,2).next() }}", {}),
    # --- value rendering edges ------------------------------------------------------
    ("repr-str-quoting", "{{ ['it\\'s', 'a\"b', 'x\\ny', 'é', 'both\\'\"', '\\\\'] }}", {}),
    ("repr-nested", "{{ {'a': [1, {'b': none}], 't': (1,)} }}", {}),
    ("repr-items-tuple", "{% for p in d | items %}{{ p }}{% endfor %}", {"d": {"a": 1}}),
    ("repr-namespace", "{{ namespace(a=1) }}", {}),
    ("safe-concat-tilde", "{{ ('<a>' | safe) ~ '<b>' }}", {}),
    ("safe-concat-plus", "{{ ('<a>' | safe) + '<b>' }}", {}),
    ("safe-is-string", "{{ ('a' | safe) is string }}", {}),
    ("safe-tojson", "{{ ('<a>' | safe) | tojson }}", {}),
    ("macro-return-concat", "{% macro f() %}<a>{% endmacro %}{{ f() ~ '<b>' }}{{ f() + '&' }}", {}),
    ("tojson-tuple", "{{ (1, 'a') | tojson }}", {}),
    ("trim-non-string", "{{ none | trim }}|{{ 1 | trim }}|{{ undef | trim }}|", {}),
    ("upper-non-string", "{{ 1 | upper }}", {}),
    ("length-none", "{{ none | length }}", {}),
    ("concat-plus-none", "{{ 'a' + none }}", {}),
    ("cmp-undef-order", "{{ undef < 1 }}", {}),
    ("cmp-mixed-order", "{{ 'a' < 1 }}", {}),
    ("default-attr-chain", "{{ m.x | default('d') }}", {"m": {}}),
    ("not-precedence", "{{ not x is defined }}|{{ not 1 == 2 }}", {}),
    ("filter-then-arith", "{{ l | length - 1 }}", {"l": [1, 2]}),
    ("neg-filter", "{{ -l | length }}", {"l": [1, 2]}),
    ("test-arg-bare", "{{ 6 is divisibleby 3 and true }}", {}),
    ("call-on-attr-chain", "{{ d.get('m').upper() }}", {"d": {"m": "x"}}),
    # --- whitespace control interplay ---------------------------------------------
    ("ws-endfor-no-dash", "{%- for x in [1, 2] %}\n{{- x }}\n{% endfor %}\n\n\n{%- if true %}E{% endif %}", {}),
    ("ws-lstrip-indent", "  {% if true %}\n  X\n  {% endif %}\nY", {}),
    ("ws-comment-after-block-indent", "{% if true %}\n    {# c #}\n    X{% endif %}|", {}),
    ("ws-block-after-block-indent", "{% if true %}\n    {% if true %}Y{% endif %}\n{% endif %}|", {}),
    ("ws-comment-after-trimmed-block", "{%- if true -%}\n        {# c #}\n        {%- set z = 1 %}Z{% endif %}", {}),
    ("ws-midline-before-comment", "a  {# c #}b", {}),
    ("ws-comment-trim", "a {#- c -#} b", {}),
    ("ws-output-no-trim-blocks", "{{ 'a' }}\n{{ 'b' }}", {}),
    ("ws-plus-marker", "  {%+ if true %}X{% endif %}", {}),
    ("ws-raw-block", "{% raw %}{{ x }}{% endraw %}", {}),
]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    import jinja2
    import transformers
    from transformers.utils import chat_template_utils as ctu

    class _Frozen(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return KV_JINJA_FROZEN_NOW

    # strftime_now closes over the module-global `datetime` name at call time.
    ctu.datetime = _Frozen

    names = set()
    rows = []
    for name, tpl, ctx in CASES:
        if name in names:
            print(f"duplicate case name {name}", file=sys.stderr)
            return 1
        names.add(name)
        row = {"name": name, "template": tpl, "context": ctx}
        try:
            compiled = ctu._compile_jinja_template(tpl)
            row["rendered"] = compiled.render(**ctx)
        except Exception as e:  # noqa: BLE001 — the error class IS the golden
            row["error"] = f"{type(e).__name__}: {e}"
        rows.append(row)

    doc = {
        "_note": (
            "Per-construct Jinja parity goldens generated by "
            "gen_jinja_construct_fixtures.py through transformers' chat-template "
            "environment. A row with `rendered` must render byte-identically in "
            "the gateway executor; a row with `error` must fail to render (or "
            "compile) there too."
        ),
        "transformers_version": transformers.__version__,
        "jinja2_version": jinja2.__version__,
        "frozen_now": KV_JINJA_FROZEN_NOW.isoformat(),
        "cases": rows,
    }
    with open(sys.argv[1], "w") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    ok = sum(1 for r in rows if "rendered" in r)
    print(f"{len(rows)} cases: {ok} render, {len(rows) - ok} raise")
    return 0


if __name__ == "__main__":
    sys.exit(main())
