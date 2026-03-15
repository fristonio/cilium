// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package selector implements a Calico-compatible label selector expression language
// for matching Cilium labels.
//
// The selector language supports the following syntax:
//
//	all()                     - matches any label set
//	global()                  - alias for all()
//	has(key)                  - true if the label key exists
//	key == "value"            - true if key exists and its value equals "value"
//	key != "value"            - true if key does not exist or its value differs
//	key in {"v1", "v2"}       - true if key exists and its value is in the set
//	key not in {"v1", "v2"}   - true if key does not exist or its value is not in the set
//	key starts with "prefix"  - true if key exists and its value has the given prefix
//	key ends with "suffix"    - true if key exists and its value has the given suffix
//	key contains "substr"     - true if key exists and its value contains the substring
//	expr && expr              - logical AND
//	expr || expr              - logical OR
//	!expr                     - logical NOT
//	(expr)                    - grouping
//
// Keys may include a Cilium label source prefix separated by ':' (e.g. "k8s:app").
// Keys without a source prefix match labels from any source.
package selector

import (
	"fmt"

	"github.com/cilium/cilium/pkg/labels"
)

// Selector is a compiled Calico-compatible selector expression that can be
// evaluated against a set of Cilium labels.
type Selector struct {
	expression string
	root       node
}

// Parse compiles a Calico-compatible selector expression. Returns an error if
// the expression is syntactically invalid.
func Parse(expression string) (*Selector, error) {
	tokens, err := tokenize(expression)
	if err != nil {
		return nil, fmt.Errorf("selector tokenize error: %w", err)
	}

	p := newParser(tokens)
	root, err := p.parseSelector()
	if err != nil {
		return nil, fmt.Errorf("selector parse error: %w", err)
	}

	if tok := p.peek(); tok.typ != tokenEOF {
		return nil, fmt.Errorf("unexpected token %v at position %d after end of expression", tok, tok.pos)
	}

	return &Selector{
		expression: expression,
		root:       root,
	}, nil
}

// Matches returns true if the provided label set satisfies this selector.
func (s *Selector) Matches(ls labels.LabelMatcher) bool {
	return s.root.matches(ls)
}

// String returns the original selector expression string.
func (s *Selector) String() string {
	return s.expression
}

// NormalizedString returns a normalized representation of the compiled selector.
// This is derived from the parsed AST and may differ from the original expression
// in whitespace and quoting.
func (s *Selector) NormalizedString() string {
	return s.root.exprString()
}
