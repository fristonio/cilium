// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library_test

import (
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/cel/library"
	ciliumceltypes "github.com/cilium/cilium/pkg/cel/types"
	"github.com/cilium/cilium/pkg/labels"
)

func TestLabels(t *testing.T) {
	lbls := labels.Labels{
		"app":         labels.NewLabel("app", "frontend", labels.LabelSourceK8s),
		"env":         labels.NewLabel("env", "prod", labels.LabelSourceK8s),
		"10.0.0.0/24": {Key: "10.0.0.0/24", Source: labels.LabelSourceCIDR},
		"10.0.0.1/32": {Key: "10.0.0.1/32", Source: labels.LabelSourceCIDR},
	}
	env, err := cel.NewEnv(library.Labels(), cel.OptionalTypes())
	require.NoError(t, err)
	activation := map[string]any{library.LabelsVarName: ciliumceltypes.NewLabelMap(lbls)}
	tests := []struct {
		expression string
		want       bool
	}{
		{"lookup(\"k8s:app\").value().Value == \"frontend\"", true},
		{"lookup(\"k8s:app\").value().Source == \"k8s\"", true},
		{"lookup(\"any:env\").value().Source == \"k8s\"", true},
		{"lookup(\"reserved:app\").hasValue()", false},
		{"lookup(\"cidr:10.0.0.0/8\").value().Key == \"10.0.0.1/32\"", true},
		{"labels[\"app\"].Value == \"frontend\"", true},
		{"labels[\"app\"].Source == \"k8s\"", true},
		{"labels.size() == 4", true},
		{"labels.all(key, labels[key].Source != \"\")", true},
	}

	for _, tt := range tests {
		ast, issues := env.Compile(tt.expression)
		require.NoError(t, issues.Err())
		program, err := env.Program(ast)
		require.NoError(t, err)
		result, _, err := program.Eval(activation)
		require.NoError(t, err)
		require.Equal(t, tt.want, result.Value(), tt.expression)
	}
}
