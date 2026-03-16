// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"testing"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	labelsSelector "github.com/cilium/cilium/pkg/labels/selector"
)

// The expressions used across all benchmarks encode the same predicate:
// k8s:app == "nginx" AND env == "prod"
const (
	benchSelectorExpr = `k8s:app == "nginx" && env == "prod"`
	benchCELExpr      = `label("k8s:app") == "nginx" && label("env") == "prod"`

	// benchSelectorExprComplex and benchCELExprComplex encode the same predicate
	// as the simple variants above but use many redundant but semantically equivalent
	// sub-expressions to stress the parser.
	benchSelectorExprComplex = `k8s:app in {"nginx"} && has(env) && env == "prod" && ` +
		`k8s:app starts with "ngin" && k8s:app ends with "ginx" && k8s:app contains "gin" && ` +
		`env not in {"staging", "development", "testing"} && ` +
		`env starts with "pro" && env ends with "rod" && env contains "ro"`
	benchCELExprComplex = `label("k8s:app") in ["nginx"] && label("env") == "prod" && ` +
		`label("k8s:app").startsWith("ngin") && label("k8s:app").endsWith("ginx") && ` +
		`label("k8s:app").contains("gin") && ` +
		`!(label("env") in ["staging", "development", "testing"]) && ` +
		`label("env").startsWith("pro") && label("env").endsWith("rod") && ` +
		`label("env").contains("ro")`
)

var (
	labelSelector = &slim_metav1.LabelSelector{
		MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			"app": "nginx",
			"env": "prod",
		},
	}
)

// benchMatchLabels are the MatchLabels used to construct the LabelSelector benchmark.
var benchMatchLabels = []labels.Label{
	labels.NewLabel("app", "nginx", labels.LabelSourceK8s),
	labels.NewLabel("env", "prod", labels.LabelSourceK8s),
}

// makeBenchLabelArray returns a LabelArray of size n.
// The last two entries are always the ones all three selector types look for,
// so every Matches call returns true and we measure a full scan.
func makeBenchLabelArray(n int) labels.LabelMatcher {
	lbls := make([]string, 0, n)
	for i := 0; i < n-2; i++ {
		lbls = append(lbls, fmt.Sprintf("k8s:filler%d=value%d", i, i))
	}
	lbls = append(lbls, "k8s:app=nginx", "k8s:env=prod")
	return labels.ParseLabelArray(lbls...)
}

// ---- Construction benchmarks ------------------------------------------------

func BenchmarkParseSelector(b *testing.B) {
	b.Run("simple", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = labelsSelector.Parse(benchSelectorExpr)
		}
	})
	b.Run("complex", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = labelsSelector.Parse(benchSelectorExprComplex)
		}
	})
}

func BenchmarkParseCEL(b *testing.B) {
	b.Run("simple", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = labelsSelector.ParseCEL(benchCELExpr)
		}
	})
	b.Run("complex", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = labelsSelector.ParseCEL(benchCELExprComplex)
		}
	})
}

// ---- Match benchmarks -------------------------------------------------------

func benchmarkSelectorMatch(b *testing.B, n int) {
	b.Helper()
	s, err := labelsSelector.Parse(benchSelectorExpr)
	if err != nil {
		b.Fatal(err)
	}

	ls := makeBenchLabelArray(n)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = s.Matches(ls)
	}
}

func benchmarkCELMatch(b *testing.B, n int) {
	b.Helper()
	s, err := labelsSelector.ParseCEL(benchCELExpr)
	if err != nil {
		b.Fatal(err)
	}
	ls := makeBenchLabelArray(n)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = s.Matches(ls)
	}
}

func benchmarkLabelSelectorMatch(b *testing.B, n int) {
	b.Helper()
	reqs := LabelSelectorToRequirements(labelSelector)
	lbls := makeBenchLabelArray(n)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = MatchesRequirements(reqs, lbls)
	}
}

func BenchmarkLabelSelectorMatch(b *testing.B) { benchmarkLabelSelectorMatch(b, 4) }
func BenchmarkSelectorMatch(b *testing.B)      { benchmarkSelectorMatch(b, 4) }
func BenchmarkCELMatch(b *testing.B)           { benchmarkCELMatch(b, 4) }
