// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package selector

import (
	"fmt"
	"strings"
	"unicode"
)

type tokenType int

const (
	tokenEOF    tokenType = iota
	tokenOR               // ||
	tokenAND              // &&
	tokenNOT              // !
	tokenLP               // (
	tokenRP               // )
	tokenLBrace           // {
	tokenRBrace           // }
	tokenComma            // ,
	tokenEQ               // ==
	tokenNEQ              // !=
	tokenIdent            // identifier (unquoted key or keyword)
	tokenString           // quoted string value
)

func (t tokenType) String() string {
	switch t {
	case tokenEOF:
		return "EOF"
	case tokenOR:
		return "||"
	case tokenAND:
		return "&&"
	case tokenNOT:
		return "!"
	case tokenLP:
		return "("
	case tokenRP:
		return ")"
	case tokenLBrace:
		return "{"
	case tokenRBrace:
		return "}"
	case tokenComma:
		return ","
	case tokenEQ:
		return "=="
	case tokenNEQ:
		return "!="
	case tokenIdent:
		return "IDENT"
	case tokenString:
		return "STRING"
	default:
		return fmt.Sprintf("token(%d)", int(t))
	}
}

type token struct {
	typ   tokenType
	value string
	pos   int
}

func (t token) String() string {
	switch t.typ {
	case tokenIdent:
		return fmt.Sprintf("IDENT(%s)", t.value)
	case tokenString:
		return fmt.Sprintf("STRING(%q)", t.value)
	default:
		return t.typ.String()
	}
}

type tokenizer struct {
	input []rune
	pos   int
}

func newTokenizer(input string) *tokenizer {
	return &tokenizer{input: []rune(input)}
}

func (t *tokenizer) peek() (rune, bool) {
	if t.pos >= len(t.input) {
		return 0, false
	}
	return t.input[t.pos], true
}

func (t *tokenizer) advance() (rune, bool) {
	if t.pos >= len(t.input) {
		return 0, false
	}
	r := t.input[t.pos]
	t.pos++
	return r, true
}

func (t *tokenizer) skipWhitespace() {
	for t.pos < len(t.input) && unicode.IsSpace(t.input[t.pos]) {
		t.pos++
	}
}

// isIdentRune returns true for runes that can appear in an identifier.
// Identifiers can include letters, digits, hyphens, underscores, slashes,
// dots, and colons (for Cilium source-prefixed keys like "k8s:app").
func isIdentStartRune(r rune) bool {
	return unicode.IsLetter(r) || r == '_' || r == '$'
}

func isIdentContinueRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) ||
		r == '-' || r == '_' || r == '/' || r == '.' || r == ':'
}

func (t *tokenizer) nextToken() (token, error) {
	t.skipWhitespace()

	startPos := t.pos
	r, ok := t.advance()
	if !ok {
		return token{typ: tokenEOF, pos: startPos}, nil
	}

	switch r {
	case '(':
		return token{typ: tokenLP, value: "(", pos: startPos}, nil
	case ')':
		return token{typ: tokenRP, value: ")", pos: startPos}, nil
	case '{':
		return token{typ: tokenLBrace, value: "{", pos: startPos}, nil
	case '}':
		return token{typ: tokenRBrace, value: "}", pos: startPos}, nil
	case ',':
		return token{typ: tokenComma, value: ",", pos: startPos}, nil

	case '|':
		next, ok := t.peek()
		if ok && next == '|' {
			t.advance()
			return token{typ: tokenOR, value: "||", pos: startPos}, nil
		}
		return token{}, fmt.Errorf("unexpected character '|' at position %d, expected '||'", startPos)

	case '&':
		next, ok := t.peek()
		if ok && next == '&' {
			t.advance()
			return token{typ: tokenAND, value: "&&", pos: startPos}, nil
		}
		return token{}, fmt.Errorf("unexpected character '&' at position %d, expected '&&'", startPos)

	case '!':
		next, ok := t.peek()
		if ok && next == '=' {
			t.advance()
			return token{typ: tokenNEQ, value: "!=", pos: startPos}, nil
		}
		return token{typ: tokenNOT, value: "!", pos: startPos}, nil

	case '=':
		next, ok := t.peek()
		if ok && next == '=' {
			t.advance()
			return token{typ: tokenEQ, value: "==", pos: startPos}, nil
		}
		return token{}, fmt.Errorf("unexpected character '=' at position %d, expected '=='", startPos)

	case '"', '\'':
		quote := r
		var sb strings.Builder
		for {
			c, ok := t.advance()
			if !ok {
				return token{}, fmt.Errorf("unterminated string starting at position %d", startPos)
			}
			if c == rune(quote) {
				break
			}
			if c == '\\' {
				escaped, ok := t.advance()
				if !ok {
					return token{}, fmt.Errorf("unterminated escape sequence at position %d", t.pos-1)
				}
				switch escaped {
				case 'n':
					sb.WriteRune('\n')
				case 't':
					sb.WriteRune('\t')
				case 'r':
					sb.WriteRune('\r')
				default:
					sb.WriteRune(escaped)
				}
			} else {
				sb.WriteRune(c)
			}
		}
		return token{typ: tokenString, value: sb.String(), pos: startPos}, nil

	default:
		if isIdentStartRune(r) {
			var sb strings.Builder
			sb.WriteRune(r)
			for {
				c, ok := t.peek()
				if !ok {
					break
				}
				if isIdentContinueRune(c) {
					sb.WriteRune(c)
					t.advance()
				} else {
					break
				}
			}
			return token{typ: tokenIdent, value: sb.String(), pos: startPos}, nil
		}
		return token{}, fmt.Errorf("unexpected character %q at position %d", r, startPos)
	}
}

// tokenize returns all tokens for the given input expression.
func tokenize(input string) ([]token, error) {
	t := newTokenizer(input)
	var tokens []token
	for {
		tok, err := t.nextToken()
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, tok)
		if tok.typ == tokenEOF {
			break
		}
	}
	return tokens, nil
}
