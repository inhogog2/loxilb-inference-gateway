/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * ai_kv_jinja_builtin.go — filters, tests, methods and globals of the
 * template executor.
 *
 * Each builtin reproduces the Jinja / CPython function it is named after for
 * the value model's types and REFUSES (returns an error) wherever the Go
 * result could differ: unsupported argument forms, float results, locale-
 * dependent formatting, and case mappings that expand or depend on context
 * in Python. A refusal faults the render; it never yields different bytes.
 */

package loxinet

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// kvJjKw is one keyword argument, kept in call order.
type kvJjKw struct {
	name string
	val  any
}

type kvJjArgs struct {
	pos []any
	kw  []kvJjKw
}

// arg returns positional i, else keyword name, else def; ok=false when the
// argument was not supplied at all.
func (a *kvJjArgs) arg(i int, name string, def any) (any, bool) {
	if i >= 0 && i < len(a.pos) {
		return a.pos[i], true
	}
	for _, k := range a.kw {
		if k.name == name {
			return k.val, true
		}
	}
	return def, false
}

// check refuses more positional arguments than max or keywords outside the
// allowed names, as Python would raise TypeError.
func (a *kvJjArgs) check(what string, max int, names ...string) error {
	if len(a.pos) > max {
		return fmt.Errorf("%s takes at most %d positional arguments", what, max)
	}
	for _, k := range a.kw {
		ok := false
		for i, n := range names {
			if k.name == n {
				if i < len(a.pos) {
					return fmt.Errorf("%s got multiple values for %q", what, n)
				}
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%s got an unexpected keyword argument %q", what, k.name)
		}
	}
	return nil
}

func kvJjIntArg(v any, what string) (int, error) {
	if n, ok := kvJjNum(v); ok {
		return n, nil
	}
	return 0, fmt.Errorf("%s: expected an integer, got %s", what, kvJjTypeName(v))
}

func kvJjStrArg(v any, what string) (string, error) {
	if s, ok := kvJjStr(v); ok {
		return s, nil
	}
	return "", fmt.Errorf("%s: expected a string, got %s", what, kvJjTypeName(v))
}

// kvJjBuiltin is a Python-level callable (a Jinja global or a bound method).
type kvJjBuiltin struct {
	name string
	fn   func(rt *kvJjRT, a *kvJjArgs) (any, error)
}

// kvJjRaised is the error a template's raise_exception(msg) produces — the
// template itself refusing the conversation (e.g. roles not alternating).
// It is distinguishable from executor faults so callers can report it as a
// typed refusal.
type kvJjRaised struct{ msg string }

func (e *kvJjRaised) Error() string { return "jinja: template raised: " + e.msg }

// kvJjMaxRange is the sandbox's MAX_RANGE: longer ranges raise there.
const kvJjMaxRange = 100000

var kvJjGlobals = map[string]any{
	"range": &kvJjBuiltin{name: "range", fn: func(rt *kvJjRT, a *kvJjArgs) (any, error) {
		if len(a.kw) != 0 || len(a.pos) < 1 || len(a.pos) > 3 {
			return nil, fmt.Errorf("range expects 1 to 3 positional arguments")
		}
		n := make([]int, len(a.pos))
		for i, v := range a.pos {
			x, err := kvJjIntArg(v, "range")
			if err != nil {
				return nil, err
			}
			n[i] = x
		}
		start, stop, step := 0, n[0], 1
		if len(n) >= 2 {
			start, stop = n[0], n[1]
		}
		if len(n) == 3 {
			step = n[2]
		}
		if step == 0 {
			return nil, fmt.Errorf("range() arg 3 must not be zero")
		}
		var out []any
		for i := start; (step > 0 && i < stop) || (step < 0 && i > stop); i += step {
			if len(out) >= kvJjMaxRange {
				return nil, fmt.Errorf("range too big")
			}
			out = append(out, i)
		}
		if out == nil {
			out = []any{}
		}
		return out, nil
	}},
	"namespace": &kvJjBuiltin{name: "namespace", fn: func(rt *kvJjRT, a *kvJjArgs) (any, error) {
		ns := &kvJjNS{attrs: map[string]any{}}
		if len(a.pos) > 1 {
			return nil, fmt.Errorf("namespace expects at most one positional argument")
		}
		if len(a.pos) == 1 {
			d, ok := a.pos[0].(*kvJjDict)
			if !ok {
				return nil, fmt.Errorf("namespace: positional argument must be a dict")
			}
			for _, k := range d.keys {
				ns.attrs[k] = d.vals[k]
			}
		}
		for _, k := range a.kw {
			ns.attrs[k.name] = k.val
		}
		return ns, nil
	}},
	"dict": &kvJjBuiltin{name: "dict", fn: func(rt *kvJjRT, a *kvJjArgs) (any, error) {
		if len(a.pos) != 0 {
			return nil, fmt.Errorf("dict: positional arguments unsupported")
		}
		d := kvJjNewDict()
		for _, k := range a.kw {
			d.set(k.name, k.val)
		}
		return d, nil
	}},
	"raise_exception": &kvJjBuiltin{name: "raise_exception", fn: func(rt *kvJjRT, a *kvJjArgs) (any, error) {
		if len(a.pos) != 1 || len(a.kw) != 0 {
			return nil, fmt.Errorf("raise_exception expects one argument")
		}
		msg, err := kvJjToStr(a.pos[0])
		if err != nil {
			return nil, err
		}
		return nil, &kvJjRaised{msg: msg}
	}},
}

// kvJjStrftimeNow returns the strftime_now global bound to clock. The chat
// context installs it only when the profile declares a clock policy.
func kvJjStrftimeNow(clock func() time.Time) *kvJjBuiltin {
	return &kvJjBuiltin{name: "strftime_now", fn: func(rt *kvJjRT, a *kvJjArgs) (any, error) {
		if len(a.pos) != 1 || len(a.kw) != 0 {
			return nil, fmt.Errorf("strftime_now expects one argument")
		}
		f, err := kvJjStrArg(a.pos[0], "strftime_now")
		if err != nil {
			return nil, err
		}
		return kvJjStrftime(clock(), f)
	}}
}

var (
	kvJjAbbrDays    = []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	kvJjAbbrMonths  = []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	kvJjFullDays    = []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	kvJjFullMonthsN = []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}
)

// kvJjStrftime is C-locale strftime for the directives a chat template can
// use to print a date; anything locale- or zone-dependent is refused.
func kvJjStrftime(t time.Time, f string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(f); i++ {
		c := f[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(f) {
			return "", fmt.Errorf("strftime: trailing %%")
		}
		switch f[i] {
		case 'a':
			b.WriteString(kvJjAbbrDays[t.Weekday()])
		case 'A':
			b.WriteString(kvJjFullDays[t.Weekday()])
		case 'b', 'h':
			b.WriteString(kvJjAbbrMonths[t.Month()-1])
		case 'B':
			b.WriteString(kvJjFullMonthsN[t.Month()-1])
		case 'd':
			fmt.Fprintf(&b, "%02d", t.Day())
		case 'e':
			fmt.Fprintf(&b, "%2d", t.Day())
		case 'm':
			fmt.Fprintf(&b, "%02d", int(t.Month()))
		case 'y':
			fmt.Fprintf(&b, "%02d", t.Year()%100)
		case 'Y':
			fmt.Fprintf(&b, "%d", t.Year())
		case 'H':
			fmt.Fprintf(&b, "%02d", t.Hour())
		case 'I':
			h := t.Hour() % 12
			if h == 0 {
				h = 12
			}
			fmt.Fprintf(&b, "%02d", h)
		case 'M':
			fmt.Fprintf(&b, "%02d", t.Minute())
		case 'S':
			fmt.Fprintf(&b, "%02d", t.Second())
		case 'p':
			if t.Hour() < 12 {
				b.WriteString("AM")
			} else {
				b.WriteString("PM")
			}
		case 'j':
			fmt.Fprintf(&b, "%03d", t.YearDay())
		case '%':
			b.WriteByte('%')
		default:
			return "", fmt.Errorf("strftime: unsupported directive %%%c", f[i])
		}
	}
	return b.String(), nil
}

// ---------------------------------------------------------------------------
// Python text helpers.

// kvJjPySpace is str.isspace: Unicode whitespace plus the ASCII information
// separators \x1c-\x1f that Go's unicode.IsSpace leaves out.
func kvJjPySpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

func kvJjPyStrip(s string, chars any, left, right bool) (string, error) {
	if chars == nil {
		if left {
			s = strings.TrimLeftFunc(s, kvJjPySpace)
		}
		if right {
			s = strings.TrimRightFunc(s, kvJjPySpace)
		}
		return s, nil
	}
	c, err := kvJjStrArg(chars, "strip")
	if err != nil {
		return "", err
	}
	if left {
		s = strings.TrimLeft(s, c)
	}
	if right {
		s = strings.TrimRight(s, c)
	}
	return s, nil
}

// kvJjCaseUnsafe reports a rune whose Python case mapping is not the simple
// one-to-one mapping Go applies (expansions such as ß -> SS, the dotted
// capital I, and the context-dependent final sigma).
func kvJjCaseUnsafe(r rune) bool {
	switch {
	case r == 0xdf, r == 0x130, r == 0x149, r == 0x1f0, r == 0x390, r == 0x3a3, r == 0x3b0, r == 0x587:
		return true
	case r >= 0x1e96 && r <= 0x1e9a, r >= 0x1f50 && r <= 0x1f56, r >= 0x1f80 && r <= 0x1fff:
		return true
	case r >= 0xfb00 && r <= 0xfb17:
		return true
	}
	return false
}

func kvJjCaseMap(s string, m func(rune) rune) (string, error) {
	for _, r := range s {
		if r >= 0x80 && kvJjCaseUnsafe(r) {
			return "", fmt.Errorf("case mapping of %q is unsupported", r)
		}
	}
	return strings.Map(m, s), nil
}

func kvJjPyCapitalize(s string) (string, error) {
	if s == "" {
		return s, nil
	}
	r, n := utf8.DecodeRuneInString(s)
	first, err := kvJjCaseMap(string(r), unicode.ToTitle)
	if err != nil {
		return "", err
	}
	rest, err := kvJjCaseMap(s[n:], unicode.ToLower)
	if err != nil {
		return "", err
	}
	return first + rest, nil
}

// kvJjPyTitle is str.title: a cased character following an uncased one is
// title-cased, every other cased character lower-cased.
func kvJjPyTitle(s string) (string, error) {
	var b strings.Builder
	prevCased := false
	for _, r := range s {
		if r >= 0x80 && kvJjCaseUnsafe(r) {
			return "", fmt.Errorf("case mapping of %q is unsupported", r)
		}
		cased := unicode.IsUpper(r) || unicode.IsLower(r) || unicode.IsTitle(r)
		if cased && !prevCased {
			b.WriteRune(unicode.ToTitle(r))
		} else if cased {
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
		prevCased = cased
	}
	return b.String(), nil
}

// kvJjJinjaTitle is Jinja's |title filter (not str.title): words split on
// runs of "-", whitespace and opening brackets; each word's first character
// upper-cased and the rest lower-cased.
func kvJjJinjaTitle(s string) (string, error) {
	isSep := func(r rune) bool {
		return r == '-' || r == '(' || r == '{' || r == '[' || r == '<' || kvJjPySpace(r)
	}
	var b strings.Builder
	start := true
	for _, r := range s {
		if r >= 0x80 && kvJjCaseUnsafe(r) {
			return "", fmt.Errorf("case mapping of %q is unsupported", r)
		}
		switch {
		case isSep(r):
			b.WriteRune(r)
			start = true
		case start:
			b.WriteRune(unicode.ToUpper(r))
			start = false
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String(), nil
}

// kvJjPySplit is str.split(sep=None, maxsplit=-1).
func kvJjPySplit(s string, sep any, maxsplit int) ([]any, error) {
	var parts []string
	if sep == nil {
		fields := strings.FieldsFunc(s, kvJjPySpace)
		if maxsplit >= 0 && len(fields) > maxsplit+1 {
			// Re-split keeping the remainder intact after maxsplit cuts.
			rest := strings.TrimLeftFunc(s, kvJjPySpace)
			parts = nil
			for i := 0; i < maxsplit; i++ {
				j := strings.IndexFunc(rest, kvJjPySpace)
				parts = append(parts, rest[:j])
				rest = strings.TrimLeftFunc(rest[j:], kvJjPySpace)
			}
			parts = append(parts, rest)
		} else {
			parts = fields
		}
	} else {
		sp, err := kvJjStrArg(sep, "split")
		if err != nil {
			return nil, err
		}
		if sp == "" {
			return nil, fmt.Errorf("split: empty separator")
		}
		n := -1
		if maxsplit >= 0 {
			n = maxsplit + 1
		}
		parts = strings.SplitN(s, sp, n)
	}
	out := make([]any, len(parts))
	for i, p := range parts {
		out[i] = p
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Methods on str and dict values (Python-level attribute calls).

var kvJjStrMethods = map[string]bool{
	"startswith": true, "endswith": true, "split": true, "strip": true, "lstrip": true,
	"rstrip": true, "upper": true, "lower": true, "title": true, "capitalize": true,
	"replace": true, "find": true, "join": true,
}

var kvJjDictMethods = map[string]bool{"get": true, "items": true, "keys": true, "values": true}

// Python attribute names that exist on the type but that the executor does
// not implement: reaching one must refuse, not fall back to a dict key.
var kvJjStrAttrs = []string{
	"capitalize", "casefold", "center", "count", "encode", "endswith", "expandtabs", "find",
	"format", "format_map", "index", "isalnum", "isalpha", "isascii", "isdecimal",
	"isdigit", "isidentifier", "islower", "isnumeric", "isprintable", "isspace", "istitle",
	"isupper", "join", "ljust", "lower", "lstrip", "maketrans", "partition", "removeprefix",
	"removesuffix", "replace", "rfind", "rindex", "rjust", "rpartition", "rsplit", "rstrip",
	"split", "splitlines", "startswith", "strip", "swapcase", "title", "translate", "upper",
	"zfill",
}
var kvJjDictAttrs = []string{"clear", "copy", "fromkeys", "get", "items", "keys", "pop", "popitem", "setdefault", "update", "values"}
var kvJjListAttrs = []string{"append", "clear", "copy", "count", "extend", "index", "insert", "pop", "remove", "reverse", "sort"}

func kvJjHasAttrName(names []string, n string) bool {
	for _, x := range names {
		if x == n {
			return true
		}
	}
	return false
}

// kvJjCallMethod calls obj.name(args) for the implemented methods.
func kvJjCallMethod(obj any, name string, a *kvJjArgs) (any, error) {
	if s, ok := kvJjStr(obj); ok {
		if !kvJjStrMethods[name] {
			return nil, fmt.Errorf("unsupported method str.%s", name)
		}
		return kvJjStrMethod(s, name, a)
	}
	if d, ok := obj.(*kvJjDict); ok {
		if !kvJjDictMethods[name] {
			return nil, fmt.Errorf("unsupported method dict.%s", name)
		}
		switch name {
		case "get":
			if err := a.check("dict.get", 2); err != nil {
				return nil, err
			}
			k, ok := a.arg(0, "", nil)
			if !ok {
				return nil, fmt.Errorf("dict.get expects a key")
			}
			def, _ := a.arg(1, "", nil)
			if ks, ok := kvJjStr(k); ok {
				if v, ok := d.get(ks); ok {
					return v, nil
				}
			}
			return def, nil
		case "items", "keys", "values":
			if len(a.pos) != 0 || len(a.kw) != 0 {
				return nil, fmt.Errorf("dict.%s takes no arguments", name)
			}
			out := make([]any, 0, len(d.keys))
			for _, k := range d.keys {
				switch name {
				case "items":
					out = append(out, kvJjTuple{k, d.vals[k]})
				case "keys":
					out = append(out, k)
				default:
					out = append(out, d.vals[k])
				}
			}
			// A dict view: iterable, not indexable, repr differs from a list.
			return kvJjGen(out), nil
		}
	}
	if _, ok := obj.(kvJjUndef); ok {
		return nil, fmt.Errorf("method %q of undefined value", name)
	}
	return nil, fmt.Errorf("unsupported method %s.%s", kvJjTypeName(obj), name)
}

func kvJjStrMethod(s, name string, a *kvJjArgs) (any, error) {
	switch name {
	case "startswith", "endswith":
		if len(a.pos) != 1 || len(a.kw) != 0 {
			return nil, fmt.Errorf("str.%s: only the prefix argument is supported", name)
		}
		var cands []string
		if t, ok := a.pos[0].(kvJjTuple); ok {
			for _, x := range t {
				c, err := kvJjStrArg(x, name)
				if err != nil {
					return nil, err
				}
				cands = append(cands, c)
			}
		} else {
			c, err := kvJjStrArg(a.pos[0], name)
			if err != nil {
				return nil, err
			}
			cands = []string{c}
		}
		for _, c := range cands {
			if (name == "startswith" && strings.HasPrefix(s, c)) || (name == "endswith" && strings.HasSuffix(s, c)) {
				return true, nil
			}
		}
		return false, nil
	case "split":
		if err := a.check("str.split", 2, "sep", "maxsplit"); err != nil {
			return nil, err
		}
		sep, _ := a.arg(0, "sep", nil)
		ms, _ := a.arg(1, "maxsplit", -1)
		m, err := kvJjIntArg(ms, "split")
		if err != nil {
			return nil, err
		}
		return kvJjPySplit(s, sep, m)
	case "strip", "lstrip", "rstrip":
		if err := a.check("str."+name, 1, "chars"); err != nil {
			return nil, err
		}
		c, _ := a.arg(0, "chars", nil)
		return kvJjPyStrip(s, c, name != "rstrip", name != "lstrip")
	case "upper", "lower", "title", "capitalize":
		if len(a.pos) != 0 || len(a.kw) != 0 {
			return nil, fmt.Errorf("str.%s takes no arguments", name)
		}
		switch name {
		case "upper":
			return kvJjCaseMap(s, unicode.ToUpper)
		case "lower":
			return kvJjCaseMap(s, unicode.ToLower)
		case "title":
			return kvJjPyTitle(s)
		}
		return kvJjPyCapitalize(s)
	case "replace":
		if err := a.check("str.replace", 3); err != nil {
			return nil, err
		}
		if len(a.pos) < 2 {
			return nil, fmt.Errorf("str.replace expects old and new")
		}
		o, err := kvJjStrArg(a.pos[0], "replace")
		if err != nil {
			return nil, err
		}
		n, err := kvJjStrArg(a.pos[1], "replace")
		if err != nil {
			return nil, err
		}
		cnt := -1
		if len(a.pos) == 3 {
			if cnt, err = kvJjIntArg(a.pos[2], "replace"); err != nil {
				return nil, err
			}
		}
		return strings.Replace(s, o, n, cnt), nil
	case "find":
		if len(a.pos) != 1 || len(a.kw) != 0 {
			return nil, fmt.Errorf("str.find: only the substring argument is supported")
		}
		sub, err := kvJjStrArg(a.pos[0], "find")
		if err != nil {
			return nil, err
		}
		i := strings.Index(s, sub)
		if i < 0 {
			return -1, nil
		}
		return utf8.RuneCountInString(s[:i]), nil
	case "join":
		if len(a.pos) != 1 || len(a.kw) != 0 {
			return nil, fmt.Errorf("str.join expects one iterable")
		}
		items, err := kvJjIter(a.pos[0])
		if err != nil {
			return nil, err
		}
		parts := make([]string, len(items))
		for i, it := range items {
			p, ok := kvJjStr(it)
			if !ok {
				return nil, fmt.Errorf("str.join: sequence item %d: expected str, got %s", i, kvJjTypeName(it))
			}
			parts[i] = p
		}
		return strings.Join(parts, s), nil
	}
	return nil, fmt.Errorf("unsupported method str.%s", name)
}

// kvJjGen is a lazy iterable (a generator or dict view in Python): it can be
// iterated and filtered, but not indexed, measured or printed.
type kvJjGen []any

// kvJjIter returns the items Python iteration yields.
func kvJjIter(v any) ([]any, error) {
	switch x := v.(type) {
	case []any:
		return x, nil
	case kvJjTuple:
		return x, nil
	case kvJjGen:
		return x, nil
	case *kvJjDict:
		out := make([]any, len(x.keys))
		for i, k := range x.keys {
			out[i] = k
		}
		return out, nil
	case string, kvJjMarkup:
		s, _ := kvJjStr(v)
		out := make([]any, 0, len(s))
		for _, r := range s {
			out = append(out, string(r))
		}
		return out, nil
	case kvJjUndef:
		return nil, nil
	}
	return nil, fmt.Errorf("%s object is not iterable", kvJjTypeName(v))
}

// ---------------------------------------------------------------------------
// Filters.

type kvJjFilterFn func(rt *kvJjRT, v any, a *kvJjArgs) (any, error)

var kvJjFilters map[string]kvJjFilterFn

func init() {
	textFilter := func(name string, f func(string) (string, error)) kvJjFilterFn {
		return func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			if len(a.pos) != 0 || len(a.kw) != 0 {
				return nil, fmt.Errorf("filter %s takes no arguments", name)
			}
			s, err := kvJjToStr(v)
			if err != nil {
				return nil, err
			}
			return f(s)
		}
	}
	length := func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
		switch x := v.(type) {
		case string, kvJjMarkup:
			s, _ := kvJjStr(v)
			return utf8.RuneCountInString(s), nil
		case []any:
			return len(x), nil
		case kvJjTuple:
			return len(x), nil
		case *kvJjDict:
			return len(x.keys), nil
		case kvJjUndef:
			return 0, nil
		}
		return nil, fmt.Errorf("object of type %s has no len()", kvJjTypeName(v))
	}
	deflt := func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
		if err := a.check("default", 2, "default_value", "boolean"); err != nil {
			return nil, err
		}
		dv, _ := a.arg(0, "default_value", "")
		bv, _ := a.arg(1, "boolean", false)
		if _, u := v.(kvJjUndef); u || (kvJjTruthy(bv) && !kvJjTruthy(v)) {
			return dv, nil
		}
		return v, nil
	}
	kvJjFilters = map[string]kvJjFilterFn{
		"trim": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			if err := a.check("trim", 1, "chars"); err != nil {
				return nil, err
			}
			s, err := kvJjToStr(v)
			if err != nil {
				return nil, err
			}
			c, _ := a.arg(0, "chars", nil)
			return kvJjPyStrip(s, c, true, true)
		},
		"length": length,
		"count":  length,
		"tojson": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			if err := a.check("tojson", 4, "ensure_ascii", "indent", "separators", "sort_keys"); err != nil {
				return nil, err
			}
			j := &kvJjPyJSON{indent: -1}
			ea, _ := a.arg(0, "ensure_ascii", false)
			j.ensureASCII = kvJjTruthy(ea)
			if iv, _ := a.arg(1, "indent", nil); iv != nil {
				n, err := kvJjIntArg(iv, "tojson indent")
				if err != nil {
					return nil, err
				}
				if n < 0 {
					n = 0
				}
				j.indent = n
			}
			j.itemSep, j.keySep = ", ", ": "
			if j.indent >= 0 {
				j.itemSep = ","
			}
			if sv, _ := a.arg(2, "separators", nil); sv != nil {
				seps, ok := kvJjSeq(sv)
				if !ok || len(seps) != 2 {
					return nil, fmt.Errorf("tojson separators must be a pair")
				}
				is, ok1 := kvJjStr(seps[0])
				ks, ok2 := kvJjStr(seps[1])
				if !ok1 || !ok2 {
					return nil, fmt.Errorf("tojson separators must be strings")
				}
				j.itemSep, j.keySep = is, ks
			}
			sk, _ := a.arg(3, "sort_keys", false)
			j.sortKeys = kvJjTruthy(sk)
			return j.dump(v)
		},
		"default": deflt,
		"d":       deflt,
		"safe": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			s, err := kvJjToStr(v)
			if err != nil {
				return nil, err
			}
			return kvJjMarkup(s), nil
		},
		"string": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			if m, ok := v.(kvJjMarkup); ok {
				return m, nil
			}
			return kvJjToStr(v)
		},
		"items": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			switch x := v.(type) {
			case kvJjUndef:
				return kvJjGen(nil), nil
			case *kvJjDict:
				out := make([]any, 0, len(x.keys))
				for _, k := range x.keys {
					out = append(out, kvJjTuple{k, x.vals[k]})
				}
				return kvJjGen(out), nil
			}
			return nil, fmt.Errorf("can only get item pairs from a mapping")
		},
		"dictsort": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			if err := a.check("dictsort", 3, "case_sensitive", "by", "reverse"); err != nil {
				return nil, err
			}
			d, ok := v.(*kvJjDict)
			if !ok {
				return nil, fmt.Errorf("dictsort on %s", kvJjTypeName(v))
			}
			cs, _ := a.arg(0, "case_sensitive", false)
			by, _ := a.arg(1, "by", "key")
			rev, _ := a.arg(2, "reverse", false)
			if b, _ := kvJjStr(by); b != "key" {
				return nil, fmt.Errorf("dictsort by %v is unsupported", by)
			}
			keys := append([]string(nil), d.keys...)
			norm := func(k string) (string, error) {
				if kvJjTruthy(cs) {
					return k, nil
				}
				return kvJjCaseMap(k, unicode.ToLower)
			}
			nk := make(map[string]string, len(keys))
			for _, k := range keys {
				n, err := norm(k)
				if err != nil {
					return nil, err
				}
				nk[k] = n
			}
			sort.SliceStable(keys, func(i, j int) bool {
				if kvJjTruthy(rev) {
					return nk[keys[i]] > nk[keys[j]]
				}
				return nk[keys[i]] < nk[keys[j]]
			})
			out := make([]any, len(keys))
			for i, k := range keys {
				out[i] = kvJjTuple{k, d.vals[k]}
			}
			return out, nil
		},
		"join": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			if err := a.check("join", 2, "d", "attribute"); err != nil {
				return nil, err
			}
			sepV, _ := a.arg(0, "d", "")
			sep, err := kvJjStrArg(sepV, "join")
			if err != nil {
				return nil, err
			}
			items, err := kvJjIter(v)
			if err != nil {
				return nil, err
			}
			attr, hasAttr := a.arg(1, "attribute", nil)
			parts := make([]string, len(items))
			for i, it := range items {
				if hasAttr {
					if it, err = kvJjAttrPath(it, attr); err != nil {
						return nil, err
					}
				}
				if parts[i], err = kvJjToStr(it); err != nil {
					return nil, err
				}
			}
			return strings.Join(parts, sep), nil
		},
		"list": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			items, err := kvJjIter(v)
			if err != nil {
				return nil, err
			}
			return append([]any{}, items...), nil
		},
		"map": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			items, err := kvJjIter(v)
			if err != nil {
				return nil, err
			}
			out := make([]any, len(items))
			if len(a.pos) == 0 {
				if len(a.kw) != 1 || a.kw[0].name != "attribute" {
					return nil, fmt.Errorf("map: only map(attribute=...) or map('<filter>') is supported")
				}
				for i, it := range items {
					if out[i], err = kvJjAttrPath(it, a.kw[0].val); err != nil {
						return nil, err
					}
				}
				return kvJjGen(out), nil
			}
			name, err := kvJjStrArg(a.pos[0], "map")
			if err != nil {
				return nil, err
			}
			f, ok := kvJjFilters[name]
			if !ok {
				return nil, fmt.Errorf("no filter named %q", name)
			}
			sub := &kvJjArgs{pos: a.pos[1:], kw: a.kw}
			for i, it := range items {
				if out[i], err = f(rt, it, sub); err != nil {
					return nil, err
				}
			}
			return kvJjGen(out), nil
		},
		"replace": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			s, err := kvJjToStr(v)
			if err != nil {
				return nil, err
			}
			return kvJjStrMethod(s, "replace", a)
		},
		"upper":      textFilter("upper", func(s string) (string, error) { return kvJjCaseMap(s, unicode.ToUpper) }),
		"lower":      textFilter("lower", func(s string) (string, error) { return kvJjCaseMap(s, unicode.ToLower) }),
		"capitalize": textFilter("capitalize", kvJjPyCapitalize),
		"title":      textFilter("title", kvJjJinjaTitle),
		"first": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			items, err := kvJjIter(v)
			if err != nil {
				return nil, err
			}
			if len(items) == 0 {
				return kvJjUndef{name: "first"}, nil
			}
			return items[0], nil
		},
		"last": func(rt *kvJjRT, v any, a *kvJjArgs) (any, error) {
			if _, ok := v.(kvJjGen); ok {
				return nil, fmt.Errorf("last of an iterator")
			}
			items, err := kvJjIter(v)
			if err != nil {
				return nil, err
			}
			if len(items) == 0 {
				return kvJjUndef{name: "last"}, nil
			}
			return items[len(items)-1], nil
		},
	}
}

// kvJjAttrPath resolves Jinja's attribute="a.b" argument (dotted; integer
// parts index sequences).
func kvJjAttrPath(v, attr any) (any, error) {
	p, err := kvJjStrArg(attr, "attribute")
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(p, ".") {
		if v, err = kvJjGetItem(v, part); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Tests.

func kvJjRunTest(name string, v any, args []any) (bool, error) {
	arg := func() (any, error) {
		if len(args) != 1 {
			return nil, fmt.Errorf("test %q expects one argument", name)
		}
		return args[0], nil
	}
	if len(args) != 0 {
		switch name {
		case "divisibleby", "eq", "equalto", "==", "ne", "!=", "lt", "<", "le", "<=", "gt", ">", "ge", ">=", "in", "sameas":
		default:
			return false, fmt.Errorf("test %q takes no arguments", name)
		}
	}
	_, undef := v.(kvJjUndef)
	switch name {
	case "defined":
		return !undef, nil
	case "undefined":
		return undef, nil
	case "none":
		return v == nil, nil
	case "boolean":
		_, ok := v.(bool)
		return ok, nil
	case "true":
		b, ok := v.(bool)
		return ok && b, nil
	case "false":
		b, ok := v.(bool)
		return ok && !b, nil
	case "string":
		_, ok := kvJjStr(v)
		return ok, nil
	case "number":
		_, ok := kvJjNum(v)
		return ok, nil
	case "integer":
		_, ok := v.(int)
		return ok, nil
	case "mapping":
		_, ok := v.(*kvJjDict)
		return ok, nil
	case "iterable":
		switch v.(type) {
		case string, kvJjMarkup, []any, kvJjTuple, kvJjGen, *kvJjDict, kvJjUndef:
			return true, nil
		}
		return false, nil
	case "sequence":
		switch v.(type) {
		case string, kvJjMarkup, []any, kvJjTuple, *kvJjDict, kvJjUndef:
			return true, nil
		}
		return false, nil
	case "callable":
		switch v.(type) {
		case *kvJjMacro, *kvJjBuiltin, *kvJjBound:
			return true, nil
		}
		return false, nil
	case "odd", "even":
		n, ok := v.(int)
		if !ok {
			return false, fmt.Errorf("test %q on %s", name, kvJjTypeName(v))
		}
		return (n%2 != 0) == (name == "odd"), nil
	case "divisibleby":
		x, err := arg()
		if err != nil {
			return false, err
		}
		n, ok1 := v.(int)
		d, ok2 := x.(int)
		if !ok1 || !ok2 || d == 0 {
			return false, fmt.Errorf("divisibleby needs non-zero integers")
		}
		return n%d == 0, nil
	case "eq", "equalto", "==", "ne", "!=":
		x, err := arg()
		if err != nil {
			return false, err
		}
		eq := kvJjEqual(v, x)
		if name == "ne" || name == "!=" {
			return !eq, nil
		}
		return eq, nil
	case "lt", "<", "le", "<=", "gt", ">", "ge", ">=":
		x, err := arg()
		if err != nil {
			return false, err
		}
		op := map[string]string{"lt": "<", "le": "<=", "gt": ">", "ge": ">="}[name]
		if op == "" {
			op = name
		}
		return kvJjOrder(op, v, x)
	case "in":
		x, err := arg()
		if err != nil {
			return false, err
		}
		return kvJjContains(x, v)
	case "sameas":
		x, err := arg()
		if err != nil {
			return false, err
		}
		switch x.(type) {
		case nil, bool:
			if v == nil || x == nil {
				return v == nil && x == nil, nil
			}
			vb, ok := v.(bool)
			return ok && vb == x.(bool), nil
		}
		return false, fmt.Errorf("sameas is supported against none/true/false only")
	}
	return false, fmt.Errorf("unsupported test %q", name)
}

// kvJjOrder is Python ordering for numbers and strings; anything else raises.
func kvJjOrder(op string, l, r any) (bool, error) {
	if _, u := l.(kvJjUndef); u {
		return false, fmt.Errorf("ordering of undefined value")
	}
	if _, u := r.(kvJjUndef); u {
		return false, fmt.Errorf("ordering of undefined value")
	}
	var c int
	if li, ok := kvJjNum(l); ok {
		ri, ok := kvJjNum(r)
		if !ok {
			return false, fmt.Errorf("%q not supported between %s and %s", op, kvJjTypeName(l), kvJjTypeName(r))
		}
		c = li - ri
	} else if ls, ok := kvJjStr(l); ok {
		rs, ok := kvJjStr(r)
		if !ok {
			return false, fmt.Errorf("%q not supported between %s and %s", op, kvJjTypeName(l), kvJjTypeName(r))
		}
		c = strings.Compare(ls, rs)
	} else {
		return false, fmt.Errorf("%q not supported between %s and %s", op, kvJjTypeName(l), kvJjTypeName(r))
	}
	switch op {
	case "<":
		return c < 0, nil
	case "<=":
		return c <= 0, nil
	case ">":
		return c > 0, nil
	}
	return c >= 0, nil
}

// kvJjContains is Python `needle in container`.
func kvJjContains(container, needle any) (bool, error) {
	switch c := container.(type) {
	case string, kvJjMarkup:
		cs, _ := kvJjStr(c)
		s, ok := kvJjStr(needle)
		if !ok {
			return false, fmt.Errorf("'in <string>' requires string as left operand, not %s", kvJjTypeName(needle))
		}
		return strings.Contains(cs, s), nil
	case []any, kvJjTuple, kvJjGen:
		items, _ := kvJjIter(c)
		for _, it := range items {
			if kvJjEqual(needle, it) {
				return true, nil
			}
		}
		return false, nil
	case *kvJjDict:
		switch k := needle.(type) {
		case string, kvJjMarkup:
			ks, _ := kvJjStr(k)
			_, ok := c.get(ks)
			return ok, nil
		case []any, *kvJjDict:
			return false, fmt.Errorf("unhashable type: %s", kvJjTypeName(needle))
		}
		return false, nil
	case kvJjUndef:
		return false, nil
	}
	return false, fmt.Errorf("argument of type %s is not iterable", kvJjTypeName(container))
}
