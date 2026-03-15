// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package selector

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
)

// labelsFromStrings is a test helper that builds a LabelArray from
// "source:key=value" strings.
func labelsFromStrings(lbls ...string) labels.LabelArray {
	return labels.ParseLabelArray(lbls...)
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"",              // empty
		"key",           // bare key without operator
		"key =",         // single =
		"key == ",       // missing value
		"key in",        // missing value set
		"key in {",      // unclosed brace
		"has",           // missing parens
		"|",             // single |
		"&",             // single &
		"(key == \"v\"", // unclosed paren
	}
	for _, expr := range bad {
		_, err := Parse(expr)
		require.Error(t, err, "expected parse error for %q", expr)
	}
}

func TestAll(t *testing.T) {
	s, err := Parse("all()")
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings()))
	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx")))

	s2, err := Parse("global()")
	require.NoError(t, err)
	require.True(t, s2.Matches(labelsFromStrings()))
}

func TestHas(t *testing.T) {
	s, err := Parse(`has(app)`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
	require.True(t, s.Matches(labelsFromStrings("k8s:app=frontend", "k8s:env=prod")))
	require.False(t, s.Matches(labelsFromStrings("k8s:env=prod")))
	require.False(t, s.Matches(labelsFromStrings()))
}

func TestEquality(t *testing.T) {
	s, err := Parse(`app == "nginx"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=frontend")))
	require.False(t, s.Matches(labelsFromStrings("k8s:env=prod")))
}

func TestInequality(t *testing.T) {
	s, err := Parse(`app != "nginx"`)
	require.NoError(t, err)

	// key exists with different value → true
	require.True(t, s.Matches(labelsFromStrings("k8s:app=frontend")))
	// key does not exist → true (not equal)
	require.True(t, s.Matches(labelsFromStrings("k8s:env=prod")))
	// key exists with matching value → false
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
}

func TestIn(t *testing.T) {
	s, err := Parse(`env in {"prod", "staging"}`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:env=prod")))
	require.True(t, s.Matches(labelsFromStrings("k8s:env=staging")))
	require.False(t, s.Matches(labelsFromStrings("k8s:env=dev")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
}

func TestNotIn(t *testing.T) {
	s, err := Parse(`env not in {"prod", "staging"}`)
	require.NoError(t, err)

	require.False(t, s.Matches(labelsFromStrings("k8s:env=prod")))
	require.False(t, s.Matches(labelsFromStrings("k8s:env=staging")))
	require.True(t, s.Matches(labelsFromStrings("k8s:env=dev")))
	// key absent → true
	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
}

func TestStartsWith(t *testing.T) {
	s, err := Parse(`app starts with "front"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=frontend")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=backend")))
	require.False(t, s.Matches(labelsFromStrings("k8s:env=prod")))
}

func TestEndsWith(t *testing.T) {
	s, err := Parse(`app ends with "end"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=frontend")))
	require.True(t, s.Matches(labelsFromStrings("k8s:app=backend")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
}

func TestContains(t *testing.T) {
	s, err := Parse(`app contains "end"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=frontend")))
	require.True(t, s.Matches(labelsFromStrings("k8s:app=backend")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
}

func TestNot(t *testing.T) {
	s, err := Parse(`!has(app)`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:env=prod")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
}

func TestAnd(t *testing.T) {
	s, err := Parse(`has(app) && env == "prod"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx", "k8s:env=prod")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx", "k8s:env=dev")))
	require.False(t, s.Matches(labelsFromStrings("k8s:env=prod")))
}

func TestOr(t *testing.T) {
	s, err := Parse(`app == "nginx" || app == "frontend"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
	require.True(t, s.Matches(labelsFromStrings("k8s:app=frontend")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=backend")))
}

func TestGrouping(t *testing.T) {
	s, err := Parse(`(app == "nginx" || app == "frontend") && env == "prod"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx", "k8s:env=prod")))
	require.True(t, s.Matches(labelsFromStrings("k8s:app=frontend", "k8s:env=prod")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=nginx", "k8s:env=dev")))
	require.False(t, s.Matches(labelsFromStrings("k8s:app=backend", "k8s:env=prod")))
}

func TestSourcePrefixedKey(t *testing.T) {
	// A source-prefixed key should only match labels with that specific source.
	s, err := Parse(`k8s:app == "nginx"`)
	require.NoError(t, err)

	require.True(t, s.Matches(labelsFromStrings("k8s:app=nginx")))
	require.False(t, s.Matches(labelsFromStrings("reserved:app=nginx")))
}

func TestString(t *testing.T) {
	expr := `has(app) && env == "prod"`
	s, err := Parse(expr)
	require.NoError(t, err)
	require.Equal(t, expr, s.String())
}

func TestEndpointSelectorWithExpression(t *testing.T) {
	// Verify that an empty label array matches none() equivalent (no matching).
	s, err := Parse(`app == "nginx"`)
	require.NoError(t, err)
	require.False(t, s.Matches(labels.LabelArray{}))

	// Verify quoted string values work.
	s2, err := Parse(`app == 'nginx'`)
	require.NoError(t, err)
	require.True(t, s2.Matches(labelsFromStrings("k8s:app=nginx")))
}
