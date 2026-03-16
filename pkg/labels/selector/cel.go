// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package selector

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/cilium/cilium/pkg/labels"
)

// labelMatcherType is the opaque CEL type representing a labels.LabelMatcher.
var labelMatcherType = cel.OpaqueType("LabelMatcher")

// labelMatcherVal wraps a labels.LabelMatcher as a CEL ref.Val so it can be
// passed as an activation variable at evaluation time.
type labelMatcherVal struct {
	ls labels.LabelMatcher
}

func (v *labelMatcherVal) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, fmt.Errorf("LabelMatcher does not support ConvertToNative")
}

func (v *labelMatcherVal) ConvertToType(t ref.Type) ref.Val {
	return types.NewErr("LabelMatcher does not support ConvertToType")
}

func (v *labelMatcherVal) Equal(other ref.Val) ref.Val {
	o, ok := other.(*labelMatcherVal)
	return types.Bool(ok && o == v)
}

func (v *labelMatcherVal) Type() ref.Type {
	return labelMatcherType
}

func (v *labelMatcherVal) Value() any {
	return v.ls
}

// celEnv is the shared CEL environment for label selector expressions.
// It declares:
//   - __lm__: an opaque LabelMatcher activation variable supplied at eval time.
//   - A GlobalMacro that rewrites label("key") → __lm__.label("key") at parse time.
//   - A MemberOverload for label on LabelMatcher that resolves label values via LookupLabel.
var celEnv *cel.Env

func init() {
	var err error
	celEnv, err = cel.NewEnv(
		cel.Variable("__lm__", labelMatcherType),
		// Rewrite global label("key") → __lm__.label("key") so the LabelMatcher
		// is the receiver and can be passed as an activation variable at eval time.
		cel.Macros(cel.GlobalMacro("label", 1, func(eh cel.MacroExprFactory, _ celast.Expr, args []celast.Expr) (celast.Expr, *cel.Error) {
			return eh.NewMemberCall("label", eh.NewIdent("__lm__"), args[0]), nil
		})),
		cel.Function("label",
			cel.MemberOverload("lm_label_string",
				[]*cel.Type{labelMatcherType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					lm, ok := lhs.(*labelMatcherVal)
					if !ok {
						return types.NewErr("label: expected LabelMatcher receiver, got %T", lhs)
					}
					key, ok := rhs.(types.String)
					if !ok {
						return types.NewErr("label: argument must be a string, got %T", rhs)
					}
					lbl := labels.ParseSelectLabel(string(key))
					v, exists := lm.ls.LookupLabel(&lbl)
					if !exists {
						return types.NewErr("label %q not found", string(key))
					}
					return types.String(v)
				}),
			),
		),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create CEL environment for label selectors: %v", err))
	}
}

// CELSelector is a compiled CEL expression evaluated against a Cilium label set.
// The expression must evaluate to bool.
//
// The custom function label(key string) string is available in expressions.
// It returns the value of the label for the given key, or causes the expression
// to evaluate to false if the label does not exist.
//
// Keys may include a Cilium source prefix separated by ':' (e.g. "k8s:app").
// Keys without a source prefix match labels from any source.
//
// Examples:
//
//	label("k8s:app") == "nginx"
//	label("k8s:env") == "prod" && label("k8s:tier") == "frontend"
type CELSelector struct {
	expression string
	program    cel.Program // compiled once; LabelMatcher is passed via activation at eval time
}

// ParseCEL compiles a CEL boolean expression for use as a label selector.
// The program is created once here and reused across all Matches calls.
// Returns an error if the expression is syntactically invalid, fails type-checking,
// or does not evaluate to bool.
func ParseCEL(expression string) (*CELSelector, error) {
	ast, iss := celEnv.Compile(expression)
	if iss.Err() != nil {
		return nil, fmt.Errorf("CEL compile error: %w", iss.Err())
	}
	checked, iss := celEnv.Check(ast)
	if iss.Err() != nil {
		return nil, fmt.Errorf("CEL type-check error: %w", iss.Err())
	}
	if checked.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("CEL expression must evaluate to bool, got %s", checked.OutputType())
	}
	prg, err := celEnv.Program(checked)
	if err != nil {
		return nil, fmt.Errorf("CEL program creation error: %w", err)
	}
	return &CELSelector{expression: expression, program: prg}, nil
}

// Matches evaluates the CEL expression against the provided label set.
// The LabelMatcher is injected as the __lm__ activation variable; no new
// program is created per call.
// Returns false if evaluation fails or a referenced label does not exist.
func (c *CELSelector) Matches(ls labels.LabelMatcher) bool {
	out, _, err := c.program.Eval(map[string]any{
		"__lm__": &labelMatcherVal{ls},
	})
	if err != nil {
		return false
	}
	v, ok := out.Value().(bool)
	return ok && v
}

// String returns the original CEL expression string.
func (c *CELSelector) String() string {
	return c.expression
}
