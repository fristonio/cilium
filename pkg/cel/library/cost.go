// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library

import (
	"math"
	"strings"
	"unicode/utf8"

	"cel.dev/cel-go/checker"
	"cel.dev/cel-go/common"
	"cel.dev/cel-go/common/ast"
	commoncost "cel.dev/cel-go/common/cost"
	"cel.dev/cel-go/common/overloads"
	"cel.dev/cel-go/common/types/ref"

	"github.com/cilium/cilium/pkg/labels"
)

// CostEstimator supplies bounds for values and functions provided by Cilium's
// CEL libraries.
type CostEstimator struct{}

func (CostEstimator) EstimateSize(checker.AstNode) *checker.SizeEstimate { return nil }

func (CostEstimator) EstimateCallCost(_, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	if overloadID == overloads.SizeString || overloadID == overloads.SizeStringInst {
		// cel-go computes string size by counting runes, so its cost depends on
		// the string length even though the default estimator treats size as O(1).
		var operand checker.AstNode
		if target != nil {
			operand = *target
		} else if len(args) > 0 {
			operand = args[0]
		}
		if operand != nil {
			size := operand.ComputedSize()
			if size == nil || size.Max == math.MaxUint64 {
				return &checker.CallEstimate{CostEstimate: checker.UnknownCostEstimate()}
			}
			return &checker.CallEstimate{CostEstimate: size.MultiplyByCostFactor(common.StringTraversalCostFactor)}
		}
	}
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
	if (overloadID == overloads.SizeString || overloadID == overloads.SizeStringInst) && len(args) > 0 {
		if value, ok := args[0].Value().(string); ok {
			cost := commoncost.SafeMultiplyByFactor(
				uint64(utf8.RuneCountInString(value)),
				common.StringTraversalCostFactor,
			)
			return &cost
		}
	}
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
