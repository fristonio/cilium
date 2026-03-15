// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package selector

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/labels"
)

// node is an AST node representing part of a selector expression.
type node interface {
	matches(ls labels.LabelMatcher) bool
	exprString() string
}

// allNode matches any label set (the all() and global() functions).
type allNode struct{}

func (n *allNode) matches(_ labels.LabelMatcher) bool { return true }
func (n *allNode) exprString() string                 { return "all()" }

// hasNode is true when the given label key exists.
type hasNode struct {
	key    labels.Label
	keyStr string
}

func newHasNode(keyStr string) *hasNode {
	return &hasNode{key: labels.ParseSelectLabel(keyStr), keyStr: keyStr}
}

func (n *hasNode) matches(ls labels.LabelMatcher) bool {
	_, exists := ls.LookupLabel(&n.key)
	return exists
}

func (n *hasNode) exprString() string { return "has(" + n.keyStr + ")" }

// eqNode is true when key exists and its value equals the expected value.
type eqNode struct {
	key    labels.Label
	keyStr string
	value  string
}

func newEqNode(keyStr, value string) *eqNode {
	return &eqNode{key: labels.ParseSelectLabel(keyStr), keyStr: keyStr, value: value}
}

func (n *eqNode) matches(ls labels.LabelMatcher) bool {
	v, exists := ls.LookupLabel(&n.key)
	return exists && v == n.value
}

func (n *eqNode) exprString() string {
	return fmt.Sprintf("%s == %q", n.keyStr, n.value)
}

// neqNode is true when the key does not exist or its value differs from the expected value.
type neqNode struct {
	key    labels.Label
	keyStr string
	value  string
}

func newNeqNode(keyStr, value string) *neqNode {
	return &neqNode{key: labels.ParseSelectLabel(keyStr), keyStr: keyStr, value: value}
}

func (n *neqNode) matches(ls labels.LabelMatcher) bool {
	v, exists := ls.LookupLabel(&n.key)
	return !exists || v != n.value
}

func (n *neqNode) exprString() string {
	return fmt.Sprintf("%s != %q", n.keyStr, n.value)
}

// inNode is true when the key exists and its value is in the given set.
type inNode struct {
	key       labels.Label
	keyStr    string
	values    map[string]struct{}
	rawValues []string
}

func newInNode(keyStr string, values []string) *inNode {
	m := make(map[string]struct{}, len(values))
	for _, v := range values {
		m[v] = struct{}{}
	}
	return &inNode{key: labels.ParseSelectLabel(keyStr), keyStr: keyStr, values: m, rawValues: values}
}

func (n *inNode) matches(ls labels.LabelMatcher) bool {
	v, exists := ls.LookupLabel(&n.key)
	if !exists {
		return false
	}
	_, ok := n.values[v]
	return ok
}

func (n *inNode) exprString() string {
	quoted := make([]string, len(n.rawValues))
	for i, v := range n.rawValues {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return n.keyStr + " in {" + strings.Join(quoted, ", ") + "}"
}

// notInNode is true when the key does not exist or its value is not in the given set.
type notInNode struct {
	key       labels.Label
	keyStr    string
	values    map[string]struct{}
	rawValues []string
}

func newNotInNode(keyStr string, values []string) *notInNode {
	m := make(map[string]struct{}, len(values))
	for _, v := range values {
		m[v] = struct{}{}
	}
	return &notInNode{key: labels.ParseSelectLabel(keyStr), keyStr: keyStr, values: m, rawValues: values}
}

func (n *notInNode) matches(ls labels.LabelMatcher) bool {
	v, exists := ls.LookupLabel(&n.key)
	if !exists {
		return true
	}
	_, ok := n.values[v]
	return !ok
}

func (n *notInNode) exprString() string {
	quoted := make([]string, len(n.rawValues))
	for i, v := range n.rawValues {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return n.keyStr + " not in {" + strings.Join(quoted, ", ") + "}"
}

// startsWithNode is true when the key exists and its value has the given prefix.
type startsWithNode struct {
	key    labels.Label
	keyStr string
	prefix string
}

func newStartsWithNode(keyStr, prefix string) *startsWithNode {
	return &startsWithNode{key: labels.ParseSelectLabel(keyStr), keyStr: keyStr, prefix: prefix}
}

func (n *startsWithNode) matches(ls labels.LabelMatcher) bool {
	v, exists := ls.LookupLabel(&n.key)
	return exists && strings.HasPrefix(v, n.prefix)
}

func (n *startsWithNode) exprString() string {
	return fmt.Sprintf("%s starts with %q", n.keyStr, n.prefix)
}

// endsWithNode is true when the key exists and its value has the given suffix.
type endsWithNode struct {
	key    labels.Label
	keyStr string
	suffix string
}

func newEndsWithNode(keyStr, suffix string) *endsWithNode {
	return &endsWithNode{key: labels.ParseSelectLabel(keyStr), keyStr: keyStr, suffix: suffix}
}

func (n *endsWithNode) matches(ls labels.LabelMatcher) bool {
	v, exists := ls.LookupLabel(&n.key)
	return exists && strings.HasSuffix(v, n.suffix)
}

func (n *endsWithNode) exprString() string {
	return fmt.Sprintf("%s ends with %q", n.keyStr, n.suffix)
}

// containsNode is true when the key exists and its value contains the given substring.
type containsNode struct {
	key    labels.Label
	keyStr string
	substr string
}

func newContainsNode(keyStr, substr string) *containsNode {
	return &containsNode{key: labels.ParseSelectLabel(keyStr), keyStr: keyStr, substr: substr}
}

func (n *containsNode) matches(ls labels.LabelMatcher) bool {
	v, exists := ls.LookupLabel(&n.key)
	return exists && strings.Contains(v, n.substr)
}

func (n *containsNode) exprString() string {
	return fmt.Sprintf("%s contains %q", n.keyStr, n.substr)
}

// notNode negates the inner node.
type notNode struct{ inner node }

func (n *notNode) matches(ls labels.LabelMatcher) bool { return !n.inner.matches(ls) }
func (n *notNode) exprString() string                  { return "!(" + n.inner.exprString() + ")" }

// andNode is true when both child nodes are true.
type andNode struct{ left, right node }

func (n *andNode) matches(ls labels.LabelMatcher) bool {
	return n.left.matches(ls) && n.right.matches(ls)
}
func (n *andNode) exprString() string {
	return "(" + n.left.exprString() + " && " + n.right.exprString() + ")"
}

// orNode is true when at least one child node is true.
type orNode struct{ left, right node }

func (n *orNode) matches(ls labels.LabelMatcher) bool {
	return n.left.matches(ls) || n.right.matches(ls)
}
func (n *orNode) exprString() string {
	return "(" + n.left.exprString() + " || " + n.right.exprString() + ")"
}

// parser is a recursive descent parser for the Calico-compatible selector language.
type parser struct {
	tokens []token
	pos    int
}

func newParser(tokens []token) *parser {
	return &parser{tokens: tokens}
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{typ: tokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *parser) consume() token {
	tok := p.peek()
	if tok.typ != tokenEOF {
		p.pos++
	}
	return tok
}

func (p *parser) expect(typ tokenType) (token, error) {
	tok := p.consume()
	if tok.typ != typ {
		return token{}, fmt.Errorf("expected %v at position %d, got %v", typ, tok.pos, tok)
	}
	return tok, nil
}

// parseSelector is the top-level entry point.
func (p *parser) parseSelector() (node, error) {
	return p.parseDisjunction()
}

// parseDisjunction parses: conjunction (|| conjunction)*
func (p *parser) parseDisjunction() (node, error) {
	left, err := p.parseConjunction()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokenOR {
		p.consume()
		right, err := p.parseConjunction()
		if err != nil {
			return nil, err
		}
		left = &orNode{left: left, right: right}
	}
	return left, nil
}

// parseConjunction parses: unary (&& unary)*
func (p *parser) parseConjunction() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokenAND {
		p.consume()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &andNode{left: left, right: right}
	}
	return left, nil
}

// parseUnary parses: !unary | atom
func (p *parser) parseUnary() (node, error) {
	if p.peek().typ == tokenNOT {
		p.consume()
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &notNode{inner: inner}, nil
	}
	return p.parseAtom()
}

// parseAtom parses a single atom: (selector) | all() | global() | has(key) | key op ...
func (p *parser) parseAtom() (node, error) {
	tok := p.peek()

	switch tok.typ {
	case tokenLP:
		p.consume()
		inner, err := p.parseSelector()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokenRP); err != nil {
			return nil, fmt.Errorf("expected ')' to close group: %w", err)
		}
		return inner, nil

	case tokenIdent:
		return p.parseIdentAtom()

	case tokenString:
		p.consume()
		return p.parseKeyAtom(tok.value)

	default:
		return nil, fmt.Errorf("unexpected token %v at position %d", tok, tok.pos)
	}
}

// parseIdentAtom handles identifiers: keywords (all, global, has) or label keys.
func (p *parser) parseIdentAtom() (node, error) {
	tok := p.consume()

	switch tok.value {
	case "all", "global":
		if _, err := p.expect(tokenLP); err != nil {
			return nil, fmt.Errorf("expected '(' after '%s'", tok.value)
		}
		if _, err := p.expect(tokenRP); err != nil {
			return nil, fmt.Errorf("expected ')' after '%s('", tok.value)
		}
		return &allNode{}, nil

	case "has":
		if _, err := p.expect(tokenLP); err != nil {
			return nil, fmt.Errorf("expected '(' after 'has'")
		}
		keyStr, err := p.parseKey()
		if err != nil {
			return nil, fmt.Errorf("expected key inside 'has(...)': %w", err)
		}
		if _, err := p.expect(tokenRP); err != nil {
			return nil, fmt.Errorf("expected ')' after 'has(%s'", keyStr)
		}
		return newHasNode(keyStr), nil

	default:
		return p.parseKeyAtom(tok.value)
	}
}

// parseKeyAtom parses the operator and operand that follow a key.
func (p *parser) parseKeyAtom(keyStr string) (node, error) {
	tok := p.peek()

	switch tok.typ {
	case tokenEQ:
		p.consume()
		value, err := p.parseStringValue()
		if err != nil {
			return nil, err
		}
		return newEqNode(keyStr, value), nil

	case tokenNEQ:
		p.consume()
		value, err := p.parseStringValue()
		if err != nil {
			return nil, err
		}
		return newNeqNode(keyStr, value), nil

	case tokenIdent:
		switch tok.value {
		case "in":
			p.consume()
			values, err := p.parseValueSet()
			if err != nil {
				return nil, err
			}
			return newInNode(keyStr, values), nil

		case "not":
			p.consume()
			inTok := p.peek()
			if inTok.typ != tokenIdent || inTok.value != "in" {
				return nil, fmt.Errorf("expected 'in' after 'not' at position %d, got %v", inTok.pos, inTok)
			}
			p.consume()
			values, err := p.parseValueSet()
			if err != nil {
				return nil, err
			}
			return newNotInNode(keyStr, values), nil

		case "starts":
			p.consume()
			withTok := p.peek()
			if withTok.typ != tokenIdent || withTok.value != "with" {
				return nil, fmt.Errorf("expected 'with' after 'starts' at position %d, got %v", withTok.pos, withTok)
			}
			p.consume()
			value, err := p.parseStringValue()
			if err != nil {
				return nil, err
			}
			return newStartsWithNode(keyStr, value), nil

		case "ends":
			p.consume()
			withTok := p.peek()
			if withTok.typ != tokenIdent || withTok.value != "with" {
				return nil, fmt.Errorf("expected 'with' after 'ends' at position %d, got %v", withTok.pos, withTok)
			}
			p.consume()
			value, err := p.parseStringValue()
			if err != nil {
				return nil, err
			}
			return newEndsWithNode(keyStr, value), nil

		case "contains":
			p.consume()
			value, err := p.parseStringValue()
			if err != nil {
				return nil, err
			}
			return newContainsNode(keyStr, value), nil

		default:
			return nil, fmt.Errorf("unexpected keyword %q after key %q at position %d", tok.value, keyStr, tok.pos)
		}

	default:
		return nil, fmt.Errorf("expected operator after key %q at position %d, got %v", keyStr, tok.pos, tok)
	}
}

// parseKey parses a key: an identifier or a quoted string.
func (p *parser) parseKey() (string, error) {
	tok := p.peek()
	switch tok.typ {
	case tokenIdent, tokenString:
		p.consume()
		return tok.value, nil
	default:
		return "", fmt.Errorf("expected key at position %d, got %v", tok.pos, tok)
	}
}

// parseStringValue parses a string value: a quoted string or an unquoted identifier.
func (p *parser) parseStringValue() (string, error) {
	tok := p.peek()
	switch tok.typ {
	case tokenString, tokenIdent:
		p.consume()
		return tok.value, nil
	default:
		return "", fmt.Errorf("expected string value at position %d, got %v", tok.pos, tok)
	}
}

// parseValueSet parses a brace-enclosed, comma-separated list of values: { v1, v2, ... }
func (p *parser) parseValueSet() ([]string, error) {
	if _, err := p.expect(tokenLBrace); err != nil {
		return nil, fmt.Errorf("expected '{' to start value set: %w", err)
	}

	var values []string
	for p.peek().typ != tokenRBrace {
		value, err := p.parseStringValue()
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		if p.peek().typ == tokenComma {
			p.consume()
		} else {
			break
		}
	}

	if _, err := p.expect(tokenRBrace); err != nil {
		return nil, fmt.Errorf("expected '}' to close value set: %w", err)
	}
	return values, nil
}
