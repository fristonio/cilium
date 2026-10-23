// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library_test

import (
	"math"
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/cel/library"
	ciliumceltypes "github.com/cilium/cilium/pkg/cel/types"
	"github.com/cilium/cilium/pkg/labels"
)

func TestLabelCostEstimation(t *testing.T) {
	env, err := cel.NewEnv(library.Labels(), cel.OptionalTypes())
	require.NoError(t, err)

	tests := []struct {
		expression string
		staticMin  uint64
		staticMax  uint64
		runtime    uint64
	}{
		{`lookup("k8s:app").hasValue()`, 11, 12, 11},
		{`lookup("cidr:10.0.0.0/8").hasValue()`, 19, math.MaxUint64, 20},
		{`lookup("k8s:app").value().Source == "k8s"`, 13, 14, 14},
		{`lookup("k8s:app").value().Value.contains("front")`, 12, 1844674407370955277, 14},
		{`lookup("k8s:app").value().Value.size() > 0`, 13, math.MaxUint64, 15},
		{`labels["app"].Value == "frontend"`, 4, 4, 4},
		{`labels["app"].Value.size() > 0`, 4, math.MaxUint64, 5},
		{`size("frontend") == 8`, 2, 2, 2},
		{`labels.exists(key, labels[key].Value == "frontend")`, 2, math.MaxUint64, 10},
		{`labels.exists(key, labels[key].Value.contains("front"))`, 2, math.MaxUint64, 10},
	}
	for _, tt := range tests {
		ast, issues := env.Compile(tt.expression)
		require.NoError(t, issues.Err())
		cost, err := env.EstimateCost(ast, library.CostEstimator{})
		require.NoError(t, err)
		require.Equal(t, tt.staticMin, cost.Min, tt.expression)
		require.Equal(t, tt.staticMax, cost.Max, tt.expression)

		program, err := env.Program(ast, cel.CostTracking(library.CostEstimator{}))
		require.NoError(t, err)
		_, details, err := program.Eval(map[string]any{
			library.LabelsVarName: ciliumceltypes.NewLabelMap(labels.Labels{
				"app": labels.NewLabel("app", "frontend", labels.LabelSourceK8s),
			}),
		})
		require.NoError(t, err)
		require.NotNil(t, details.ActualCost())
		require.Equal(t, tt.runtime, *details.ActualCost(), tt.expression)
	}
}
