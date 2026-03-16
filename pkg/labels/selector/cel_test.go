// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package selector

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
)

func TestParseCELErrors(t *testing.T) {
	bad := []struct {
		expr string
		desc string
	}{
		{`"not a bool"`, "string literal is not bool"},
		{`1 + 1`, "integer expression is not bool"},
		{`label("app"`, "unclosed parenthesis"},
		{`label()`, "label requires exactly one argument"},
		{`label("a", "b")`, "label takes one argument, not two"},
		{`undeclaredVar == "x"`, "undeclared identifier"},
	}
	for _, tc := range bad {
		_, err := ParseCEL(tc.expr)
		require.Error(t, err, "expected parse error for %q (%s)", tc.expr, tc.desc)
	}
}

func TestCELLabelEquality(t *testing.T) {
	s, err := ParseCEL(`label("app") == "nginx"`)
	require.NoError(t, err)
	require.Equal(t, `label("app") == "nginx"`, s.String())

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=frontend")))
	// label absent → error from label() → false
	require.False(t, s.Matches(labelsFromStrings("k8s:env=prod")))
	require.False(t, s.Matches(labelsFromStrings()))
}

func TestCELLabelInequality(t *testing.T) {
	s, err := ParseCEL(`label("app") != "nginx"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=frontend")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
	// label absent → error → false (not a match, not a non-match)
	require.False(t, s.Matches(labelsFromStrings()))
}

func TestCELLogicalAnd(t *testing.T) {
	s, err := ParseCEL(`label("app") == "nginx" && label("env") == "prod"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx", "k8s:env=prod")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx", "k8s:env=dev")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
	require.False(t, s.Matches(labelsFromStrings("k8s:env=prod")))
}

func TestCELLogicalOr(t *testing.T) {
	s, err := ParseCEL(`label("app") == "nginx" || label("app") == "frontend"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
	require.True(t, s.Matches(labelsFromStrings("k8s:app=frontend")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=backend")))
}

func TestCELLogicalNot(t *testing.T) {
	// has-equivalent: label present with any value
	s, err := ParseCEL(`label("app") != ""`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
	require.False(t, s.Matches(labelsFromStrings("k8s:env=prod")))
}

func TestCELLabelSourceMatching(t *testing.T) {
	// A source-prefixed key must match only that source.
	prefixed, err := ParseCEL(`label("k8s:app") == "nginx"`)
	require.NoError(t, err)
	require.True(t, prefixed.Matches(labelsFromStrings("k8s:app=nginx")))
	require.False(t, prefixed.Matches(labelsFromStrings("reserved:app=nginx")))
	require.False(t, prefixed.Matches(labelsFromStrings("any:app=nginx")))

	// An unprefixed key must match labels from any source.
	unprefixed, err := ParseCEL(`label("app") == "nginx"`)
	require.NoError(t, err)
	require.True(t, unprefixed.Matches(labelsFromStrings("k8s:app=nginx")))
	require.True(t, unprefixed.Matches(labelsFromStrings("reserved:app=nginx")))
	require.True(t, unprefixed.Matches(labelsFromStrings("any:app=nginx")))
	require.False(t, unprefixed.Matches(labelsFromStrings("k8s:app=frontend")))
	require.False(t, unprefixed.Matches(labelsFromStrings("k8s:env=nginx")))
}

func TestCELBuiltinStringFunctions(t *testing.T) {
	startsWith, err := ParseCEL(`label("app").startsWith("front")`)
	require.NoError(t, err)
	require.True(t, startsWith.Matches(labelsFromStrings("k8s:app=frontend")))
	require.False(t, startsWith.Matches(labelsFromStrings("k8s:app=backend")))
	require.False(t, startsWith.Matches(labelsFromStrings("k8s:env=prod")))

	endsWith, err := ParseCEL(`label("app").endsWith("end")`)
	require.NoError(t, err)
	require.True(t, endsWith.Matches(labelsFromStrings("k8s:app=frontend")))
	require.True(t, endsWith.Matches(labelsFromStrings("k8s:app=backend")))
	require.False(t, endsWith.Matches(labelsFromStrings("k8s:app=nginx")))

	contains, err := ParseCEL(`label("app").contains("end")`)
	require.NoError(t, err)
	require.True(t, contains.Matches(labelsFromStrings("k8s:app=frontend")))
	require.False(t, contains.Matches(labelsFromStrings("k8s:app=nginx")))
}

func TestCELK8sSet(t *testing.T) {
	// K8sSet implements LabelMatcher; keys are implicitly in the "k8s" source.
	s, err := ParseCEL(`label("app") == "nginx"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labels.K8sSet{"app": "nginx"}))
	require.False(t, s.Matches(labels.K8sSet{"app": "frontend"}))
	require.False(t, s.Matches(labels.K8sSet{}))

	// Source-prefixed key with K8sSet.
	sPrefixed, err := ParseCEL(`label("k8s:app") == "nginx"`)
	require.NoError(t, err)
	require.True(t, sPrefixed.Matches(labels.K8sSet{"app": "nginx"}))
}

func TestCELProgramReuse(t *testing.T) {
	// Verify that the same CELSelector can be used across multiple Matches calls
	// with different LabelMatchers (i.e. the program is not polluted between calls).
	s, err := ParseCEL(`label("env") == "prod"`)
	require.NoError(t, err)

	for range 5 {
		require.True(t, s.Matches(labelsFromStrings("k8s:env=prod")))
		require.False(t, s.Matches(labelsFromStrings("k8s:env=dev")))
		require.False(t, s.Matches(labelsFromStrings()))
	}
}

func TestCELGrouping(t *testing.T) {
	s, err := ParseCEL(`(label("app") == "nginx" || label("app") == "frontend") && label("env") == "prod"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx", "k8s:env=prod")))
	require.True(t, s.Matches(labelsFromStrings("k8s:app=frontend", "k8s:env=prod")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx", "k8s:env=dev")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=backend", "k8s:env=prod")))
}
