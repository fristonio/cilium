// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library

import (
	"net/netip"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	celtypes "cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	ciliumceltypes "github.com/cilium/cilium/pkg/cel/types"
	"github.com/cilium/cilium/pkg/labels"
)

const (
	LabelsVarName   = "labels"
	LookupMacroName = "lookup"

	LabelsLookupFuncName = "__labels_lookup__"
)

var (
	nativeLabelType = ciliumceltypes.NativeLabelType
	labelType       = cel.ObjectType(nativeLabelType.TypeName())
	labelsMapType   = cel.MapType(cel.StringType, labelType)
)

// Labels returns the CEL environment option for identity label expressions.
func Labels() cel.EnvOption {
	return cel.Lib(labelsLib)
}

var labelsLib = &identityLabels{}

type identityLabels struct{}

func (*identityLabels) LibraryName() string {
	return "cilium.labels"
}

func (*identityLabels) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Types(nativeLabelType),
		cel.Variable(LabelsVarName, labelsMapType),
		cel.Macros(cel.GlobalMacro(
			LookupMacroName,
			1,
			lookupMacroExpander,
			cel.MacroDocs("Looks up a label by source and key and returns an optional label."),
			cel.MacroExamples(`lookup("k8s:app").value().Value`),
		)),
		cel.Function(LabelsLookupFuncName,
			cel.Overload(
				LabelsLookupFuncName,
				[]*cel.Type{labelsMapType, cel.StringType},
				cel.OptionalType(labelType),
				cel.BinaryBinding(lookupLabel),
			),
		),
	}
}

func (*identityLabels) ProgramOptions() []cel.ProgramOption {
	return nil
}

func lookupLabel(labelMap, key ref.Val) ref.Val {
	lbls, ok := labelMap.Value().(labels.Labels)
	if !ok {
		return celtypes.NewErr("lookup() requires identity labels, got %T", labelMap.Value())
	}
	labelKey, ok := key.Value().(string)
	if !ok {
		return celtypes.NewErr("lookup() requires a string, got %T", key.Value())
	}
	parsed := labels.ParseSelectLabel(labelKey)
	lbl, exists := findLabel(lbls, &parsed)
	if !exists {
		return celtypes.OptionalNone
	}
	return celtypes.OptionalOf(nativeLabelType.Adapt(celtypes.DefaultTypeAdapter, lbl))
}

func findLabel(lbls labels.Labels, key *labels.Label) (labels.Label, bool) {
	if key.Source != labels.LabelSourceCIDR {
		lbl, ok := lbls[key.Key]
		return lbl, ok && lbl.HasKey(key)
	}
	var match labels.Label
	found := false
	for _, lbl := range lbls {
		if lbl.HasKey(key) && (!found || moreSpecificCIDR(lbl, match)) {
			match = lbl
			found = true
		}
	}
	return match, found
}

func moreSpecificCIDR(candidate, current labels.Label) bool {
	candidatePrefix, candidateOK := labelCIDRPrefix(candidate)
	currentPrefix, currentOK := labelCIDRPrefix(current)
	if candidateOK && currentOK && candidatePrefix.Bits() != currentPrefix.Bits() {
		return candidatePrefix.Bits() > currentPrefix.Bits()
	}
	if candidateOK && !currentOK {
		return true
	}
	return candidate.Key < current.Key
}

func labelCIDRPrefix(lbl labels.Label) (netip.Prefix, bool) {
	if prefix := lbl.GetCIDRPrefix(); prefix != nil {
		return *prefix, true
	}
	prefix, err := netip.ParsePrefix(strings.ReplaceAll(lbl.Key, "-", ":"))
	return prefix, err == nil
}

func lookupMacroExpander(eh cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *cel.Error) {
	return eh.NewCall(LabelsLookupFuncName, eh.NewIdent(LabelsVarName), args[0]), nil
}
