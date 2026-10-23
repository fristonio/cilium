// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cel_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/cel"
	"github.com/cilium/cilium/pkg/labels"
)

var benchmarkMatch bool

func TestLabelSelectorEnvironment(t *testing.T) {
	env, err := cel.NewEnvironment(cel.DefaultConfig, nil)
	require.NoError(t, err)

	lbls := labels.Labels{
		"app": labels.NewLabel("app", "frontend", labels.LabelSourceK8s),
		"env": labels.NewLabel("env", "prod", labels.LabelSourceK8s),
	}
	tests := []struct {
		expression string
		want       bool
	}{
		{"lookup(\"k8s:app\").value().Value == \"frontend\"", true},
		{"lookup(\"reserved:app\").hasValue()", false},
		{"labels[\"env\"].Value == \"prod\"", true},
		{"labels.exists(key, key.startsWith(\"app\"))", true},
	}
	for _, tt := range tests {
		result := env.Compile(cel.EnvTypeLabelSelector, tt.expression)
		require.NoError(t, result.Error)
		got, err := result.Evaluate(t.Context(), lbls)
		require.NoError(t, err)
		require.Equal(t, tt.want, got)
	}
}

func TestCompilerLimits(t *testing.T) {
	// Expressions without a finite static bound remain guarded by the runtime
	// cost limit.
	env, err := cel.NewEnvironment(cel.DefaultConfig, nil)
	require.NoError(t, err)
	result := env.Compile(cel.EnvTypeFlowFilter, `_flow.source_names.exists(name, name.contains("frontend"))`)
	require.NoError(t, result.Error)

	cfg := cel.DefaultConfig
	cfg.ExpressionMaxCost = 2
	env, err = cel.NewEnvironment(cfg, nil)
	require.NoError(t, err)

	result = env.Compile(cel.EnvTypeLabelSelector, `labels["app"].Value == "frontend"`)
	require.ErrorContains(t, result.Error, "exceeds limit")
	result = env.Compile(cel.EnvTypeLabelSelector, `lookup("cidr:10.0.0.0/8").hasValue() && labels["app"].Value == "frontend"`)
	require.ErrorContains(t, result.Error, "exceeds limit")

	cfg = cel.DefaultConfig
	cfg.ExpressionMaxSize = 16
	env, err = cel.NewEnvironment(cfg, nil)
	require.NoError(t, err)
	result = env.Compile(cel.EnvTypeLabelSelector, strings.Repeat(" ", 16)+"true")
	require.ErrorContains(t, result.Error, "code point size exceeds limit")

	cfg = cel.DefaultConfig
	cfg.ExpressionMaxCost = 0
	cfg.ProgramMaxCost = 1
	env, err = cel.NewEnvironment(cfg, nil)
	require.NoError(t, err)
	result = env.Compile(cel.EnvTypeFlowFilter, `_flow.verdict == Verdict.FORWARDED`)
	require.NoError(t, result.Error)
	_, err = result.Evaluate(t.Context(), &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED})
	require.ErrorContains(t, err, "cost limit exceeded")
}

func TestCompileErrors(t *testing.T) {
	env, err := cel.NewEnvironment(cel.DefaultConfig, nil)
	require.NoError(t, err)

	require.Error(t, env.Compile(cel.EnvTypeLabelSelector, "lookup(").Error)
	require.Error(t, env.Compile(cel.EnvTypeLabelSelector, "labels").Error)
	require.Error(t, env.Compile("unknown", "true").Error)
}

func BenchmarkLabelSelectorEvaluation(b *testing.B) {
	lbls := labels.Labels{
		"app": labels.NewLabel("app", "frontend", labels.LabelSourceK8s),
	}
	for _, tc := range []struct {
		name    string
		metrics *cel.Metrics
		config  cel.Config
	}{
		{name: "without metrics", config: cel.DefaultConfig},
		{name: "with metrics", metrics: cel.NewCELMetrics(), config: cel.DefaultConfig},
		{name: "without runtime cost limit", config: func() cel.Config {
			config := cel.DefaultConfig
			config.ProgramMaxCost = 0
			return config
		}()},
	} {
		b.Run(tc.name, func(b *testing.B) {
			env, err := cel.NewEnvironment(tc.config, tc.metrics)
			require.NoError(b, err)
			result := env.Compile(cel.EnvTypeLabelSelector, `labels["app"].Value == "frontend"`)
			require.NoError(b, result.Error)
			b.ReportAllocs()
			for b.Loop() {
				_, err := result.Evaluate(context.Background(), lbls)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRuntimeCostTracking(b *testing.B) {
	labelSet := labels.Labels{
		"app": labels.NewLabel("app", "frontend", labels.LabelSourceK8s),
	}
	sourceNames := make([]string, 32)
	for i := range 31 {
		key := fmt.Sprintf("key-%02d", i)
		labelSet[key] = labels.NewLabel(key, "value", labels.LabelSourceK8s)
		sourceNames[i] = fmt.Sprintf("service-%02d.example.com", i)
	}
	sourceNames[31] = "frontend.example.com"

	flow := &flowpb.Flow{
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{DestinationPort: 80},
			},
		},
		SourceNames: sourceNames,
	}

	tests := []struct {
		name       string
		envType    cel.EnvType
		expression string
		argument   any
	}{
		{
			name:       "labels/direct lookup",
			envType:    cel.EnvTypeLabelSelector,
			expression: `labels["app"].Value == "frontend"`,
			argument:   labelSet,
		},
		{
			name:       "labels/source-aware lookup",
			envType:    cel.EnvTypeLabelSelector,
			expression: `lookup("k8s:app").value().Value == "frontend"`,
			argument:   labelSet,
		},
		{
			name:       "labels/full comprehension",
			envType:    cel.EnvTypeLabelSelector,
			expression: `labels.exists(key, labels[key].Value == "missing")`,
			argument:   labelSet,
		},
		{
			name:       "flow/scalar",
			envType:    cel.EnvTypeFlowFilter,
			expression: `_flow.l4.TCP.destination_port == uint(80)`,
			argument:   flow,
		},
		{
			name:       "flow/full comprehension",
			envType:    cel.EnvTypeFlowFilter,
			expression: `_flow.source_names.exists(name, name == "missing")`,
			argument:   flow,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for _, runtimeCostLimit := range []bool{false, true} {
				name := "runtime_cost=disabled"
				cfg := cel.DefaultConfig
				if !runtimeCostLimit {
					cfg.ProgramMaxCost = 0
				} else {
					name = "runtime_cost=enabled"
				}
				b.Run(name, func(b *testing.B) {
					env, err := cel.NewEnvironment(cfg, nil)
					require.NoError(b, err)
					result := env.Compile(tt.envType, tt.expression)
					require.NoError(b, result.Error)

					b.ReportAllocs()
					for b.Loop() {
						match, err := result.Evaluate(context.Background(), tt.argument)
						if err != nil {
							b.Fatal(err)
						}
						benchmarkMatch = match
					}
				})
			}
		})
	}
}
