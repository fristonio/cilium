// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library

import (
	"math"
	"strings"
	"unicode/utf8"

	"cel.dev/cel-go/checker"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types/ref"

	"github.com/cilium/cilium/pkg/labels"
)

const (
	maxLabelKeyLen   = 317
	maxLabelValueLen = 63
	// directory is the longest identity label source.
	maxLabelSourceLen = uint64(len(labels.LabelSourceDirectory))
)

// CostEstimator supplies bounds for values and functions provided by Cilium's
// CEL libraries. When enabled, runtime cost tracking remains authoritative.
type CostEstimator struct{}

func (CostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	path := element.Path()
	if len(path) == 0 {
		return nil
	}

	if path[0] != LabelsVarName {
		expr := element.Expr()
		if expr.Kind() != ast.SelectKind || !containsLabelLookup(expr.AsSelect().Operand()) {
			return nil
		}
	}

	switch path[len(path)-1] {
	case "@keys":
		return &checker.SizeEstimate{Min: 0, Max: maxLabelKeyLen}
	case "Key":
		return &checker.SizeEstimate{Min: 0, Max: maxLabelKeyLen}
	case "Value":
		return &checker.SizeEstimate{Min: 0, Max: maxLabelValueLen}
	case "Source":
		return &checker.SizeEstimate{Min: 0, Max: maxLabelSourceLen}
	}
	return nil
}

func containsLabelLookup(expr ast.Expr) bool {
	switch expr.Kind() {
	case ast.CallKind:
		call := expr.AsCall()
		if call.FunctionName() == LabelsLookupFuncName {
			return true
		}
		if call.IsMemberFunction() && containsLabelLookup(call.Target()) {
			return true
		}
		for _, arg := range call.Args() {
			if containsLabelLookup(arg) {
				return true
			}
		}
	case ast.SelectKind:
		return containsLabelLookup(expr.AsSelect().Operand())
	}
	return false
}

func (CostEstimator) EstimateCallCost(_, overloadID string, _ *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	if overloadID != LabelsLookupFuncName {
		return nil
	}
	// A present result also materializes the native label value.
	cost := checker.CostEstimate{Min: 2, Max: math.MaxUint64}
	if len(args) > 1 && args[1].Expr().Kind() == ast.LiteralKind {
		if key, ok := args[1].Expr().AsLiteral().Value().(string); ok {
			keyCost := uint64(utf8.RuneCountInString(key))
			cost.Min += keyCost
			parsed := labels.ParseSelectLabel(key)
			if parsed.Source != labels.LabelSourceCIDR {
				cost.Max = cost.Min + 1
			}
		}
	}
	return &checker.CallEstimate{
		// Dynamic and CIDR lookups may scan a map whose cardinality is unbounded.
		CostEstimate: cost,
	}
}

func (CostEstimator) CallCost(_, overloadID string, args []ref.Val, _ ref.Val) *uint64 {
	if overloadID != LabelsLookupFuncName {
		return nil
	}
	cost := uint64(2)
	if len(args) > 1 {
		if key, ok := args[1].Value().(string); ok {
			cost += uint64(utf8.RuneCountInString(key))
			if strings.HasPrefix(key, labels.LabelSourceCIDR+labels.SourceDelimiter) && len(args) > 0 {
				if labelMap, ok := args[0].Value().(labels.Labels); ok {
					cost += uint64(len(labelMap))
				}
			}
		}
	}
	return &cost
}
