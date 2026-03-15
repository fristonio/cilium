// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"fmt"
	"strings"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/selector"
)

// SelectorExpression is a Calico-compatible selector expression string.
// An empty SelectorExpression matches nothing (i.e. is absent).
type SelectorExpression string

// IsZero reports whether the expression is empty (absent).
func (s SelectorExpression) IsZero() bool { return len(s) == 0 }

// EndpointSelector is a wrapper for k8s LabelSelector.
type EndpointSelector struct {
	*slim_metav1.LabelSelector `json:",inline"`

	// SelectionExpression is an optional Calico-compatible selector expression.
	// When set, an endpoint must satisfy both this expression and the
	// k8s LabelSelector (AND semantics). If only the expression is needed, the
	// LabelSelector may be left empty (which by itself matches all endpoints).
	//
	// The language supports: all(), global(), has(key), key == "v", key != "v",
	// key in {"v1","v2"}, key not in {"v1","v2"}, key starts with "p",
	// key ends with "s", key contains "sub", and the boolean operators
	// &&, ||, ! and grouping with parentheses.
	//
	// Label keys may optionally include a Cilium source prefix separated by ':'
	// (e.g. "k8s:app"). Keys without a source prefix match labels from any source.
	//
	// +kubebuilder:validation:Optional
	SelectionExpression SelectorExpression `json:"selectionExpression,omitempty"`

	// cachedLabelSelectorString is the cached representation of the
	// LabelSelector for this EndpointSelector. It is populated when
	// EndpointSelectors are created via `NewESFromMatchRequirements`. It is
	// immutable after its creation.
	cachedLabelSelectorString string `json:"-"`

	// Generated indicates whether the rule was generated based on other rules
	// or provided by user
	Generated bool `json:"-"`
}

// buildSelectorKey constructs the full selector key from the k8s LabelSelector
// string and the optional SelectionExpression. This is the canonical form stored
// in cachedLabelSelectorString and returned by SelectorKey.
func buildSelectorKey(ls *slim_metav1.LabelSelector, expr SelectorExpression) string {
	base := ls.String()
	if !expr.IsZero() {
		return base + " && (" + string(expr) + ")"
	}
	return base
}

func (n EndpointSelector) SelectorKey() string {
	if n.cachedLabelSelectorString != "" {
		return n.cachedLabelSelectorString
	}
	return buildSelectorKey(n.LabelSelector, n.SelectionExpression)
}

// Used for `omitzero` json tag.
func (n *EndpointSelector) IsZero() bool {
	return n.LabelSelector == nil && n.SelectionExpression.IsZero()
}

// LabelSelectorString returns a user-friendly string representation of
// EndpointSelector.
func (n *EndpointSelector) LabelSelectorString() string {
	if n != nil && n.LabelSelector == nil {
		return "<all>"
	}
	return slim_metav1.FormatLabelSelector(n.LabelSelector)
}

// String returns a string representation of EndpointSelector.
func (n EndpointSelector) String() string {
	j, _ := json.Marshal(n.LabelSelector)
	return string(j)
}

// CachedString returns the cached string representation of the LabelSelector
// for this EndpointSelector.
func (n EndpointSelector) CachedString() string {
	return n.cachedLabelSelectorString
}

// UnmarshalJSON unmarshals the endpoint selector from the byte array.
func (n *EndpointSelector) UnmarshalJSON(b []byte) error {
	// Always initialize LabelSelector to distinguish an empty selector
	// (matches all endpoints) from an absent selector, matching historical
	// behavior relied on by policyapi.Rule field disambiguation.
	n.LabelSelector = &slim_metav1.LabelSelector{}
	// Use a type alias to invoke standard JSON unmarshaling without triggering
	// this method recursively. The embedded *LabelSelector fields are inlined
	// at the JSON level (json:",inline"), and SelectionExpression carries its
	// own tag, so the standard decoder handles everything correctly.
	type plain EndpointSelector
	return json.Unmarshal(b, (*plain)(n))
}

// HasKeyPrefix checks if the endpoint selector contains the given key prefix in
// its MatchLabels map and MatchExpressions slice.
func (n EndpointSelector) HasKeyPrefix(prefix string) bool {
	for k := range n.MatchLabels {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	for _, v := range n.MatchExpressions {
		if strings.HasPrefix(v.Key, prefix) {
			return true
		}
	}
	return false
}

// HasKey checks if the endpoint selector contains the given key in
// its MatchLabels map or in its MatchExpressions slice.
func (n EndpointSelector) HasKey(key string) bool {
	if _, ok := n.MatchLabels[key]; ok {
		return true
	}
	for _, v := range n.MatchExpressions {
		if v.Key == key {
			return true
		}
	}
	return false
}

// GetMatch checks for a match on the specified key, and returns the value that
// the key must match, and true. If a match cannot be found, returns nil, false.
func (n EndpointSelector) GetMatch(key string) ([]string, bool) {
	if value, ok := n.MatchLabels[key]; ok {
		return []string{value}, true
	}
	for _, v := range n.MatchExpressions {
		if v.Key == key && v.Operator == slim_metav1.LabelSelectorOpIn {
			return v.Values, true
		}
	}
	return nil, false
}

// NewESFromLabels creates a new endpoint selector from the given labels.
func NewESFromLabels(lbls ...labels.Label) EndpointSelector {
	ml := map[string]string{}
	for _, lbl := range lbls {
		ml[lbl.GetExtendedKey()] = lbl.Value
	}

	return NewESFromMatchRequirements(ml, nil)
}

// NewESFromMatchRequirements creates a new endpoint selector from the given
// match specifications: An optional set of labels that must match, and
// an optional slice of LabelSelectorRequirements.
//
// If the caller intends to reuse 'matchLabels' or 'reqs' after creating the
// EndpointSelector, they must make a copy of the parameter.
func NewESFromMatchRequirements(matchLabels map[string]string, reqs []slim_metav1.LabelSelectorRequirement) EndpointSelector {
	labelSelector := &slim_metav1.LabelSelector{
		MatchLabels:      matchLabels,
		MatchExpressions: reqs,
	}
	// SelectionExpression is always empty for programmatically constructed
	// selectors, so buildSelectorKey just returns labelSelector.String().
	return EndpointSelector{
		LabelSelector:             labelSelector,
		cachedLabelSelectorString: buildSelectorKey(labelSelector, ""),
	}
}

// newReservedEndpointSelector returns a selector that matches on all
// endpoints with the specified reserved label.
func newReservedEndpointSelector(ID string) EndpointSelector {
	reservedLabels := labels.NewLabel(ID, "", labels.LabelSourceReserved)
	return NewESFromLabels(reservedLabels)
}

var (
	// WildcardEndpointSelector is a wildcard endpoint selector matching
	// all endpoints that can be described with labels.
	WildcardEndpointSelector = NewESFromLabels()

	// ReservedEndpointSelectors map reserved labels to EndpointSelectors
	// that will match those endpoints.
	ReservedEndpointSelectors = map[string]EndpointSelector{
		labels.IDNameHost:       newReservedEndpointSelector(labels.IDNameHost),
		labels.IDNameRemoteNode: newReservedEndpointSelector(labels.IDNameRemoteNode),
		labels.IDNameWorld:      newReservedEndpointSelector(labels.IDNameWorld),
		labels.IDNameWorldIPv4:  newReservedEndpointSelector(labels.IDNameWorldIPv4),
		labels.IDNameWorldIPv6:  newReservedEndpointSelector(labels.IDNameWorldIPv6),
	}
)

// NewESFromK8sLabelSelector returns a new endpoint selector from the label
// where it the given srcPrefix will be encoded in the label's keys.
func NewESFromK8sLabelSelector(srcPrefix string, lss ...*slim_metav1.LabelSelector) EndpointSelector {
	var (
		matchLabels      map[string]string
		matchExpressions []slim_metav1.LabelSelectorRequirement
	)
	for _, ls := range lss {
		if ls == nil {
			continue
		}
		if ls.MatchLabels != nil {
			if matchLabels == nil {
				matchLabels = map[string]string{}
			}
			for k, v := range ls.MatchLabels {
				matchLabels[labels.NewSourceEncodedLabelKey(srcPrefix, k)] = v
			}
		}
		if ls.MatchExpressions != nil {
			if matchExpressions == nil {
				matchExpressions = make([]slim_metav1.LabelSelectorRequirement, 0, len(ls.MatchExpressions))
			}
			for _, v := range ls.MatchExpressions {
				v.Key = labels.NewSourceEncodedLabelKey(srcPrefix, v.Key)
				matchExpressions = append(matchExpressions, v)
			}
		}
	}
	return NewESFromMatchRequirements(matchLabels, matchExpressions)
}

// AddMatch adds a match for 'key' == 'value' to the endpoint selector.
func (n *EndpointSelector) AddMatch(key, value string) {
	if n.MatchLabels == nil {
		n.MatchLabels = map[string]string{}
	}
	n.MatchLabels[key] = value
	n.cachedLabelSelectorString = buildSelectorKey(n.LabelSelector, n.SelectionExpression)
}

// AddMatchExpression adds a match expression to label selector of the endpoint selector.
func (n *EndpointSelector) AddMatchExpression(key string, op slim_metav1.LabelSelectorOperator, values []string) {
	n.MatchExpressions = append(n.MatchExpressions, slim_metav1.LabelSelectorRequirement{
		Key:      key,
		Operator: op,
		Values:   values,
	})
	n.cachedLabelSelectorString = buildSelectorKey(n.LabelSelector, n.SelectionExpression)
}

func (n *EndpointSelector) SetSelectionExpression(expr SelectorExpression) {
	n.SelectionExpression = expr
	n.cachedLabelSelectorString = buildSelectorKey(n.LabelSelector, n.SelectionExpression)
}

// IsWildcard returns true if the endpoint selector selects all endpoints.
func (n *EndpointSelector) IsWildcard() bool {
	return n.LabelSelector != nil &&
		len(n.LabelSelector.MatchLabels)+len(n.LabelSelector.MatchExpressions) == 0 &&
		n.SelectionExpression.IsZero()
}

func (n *EndpointSelector) Sanitize() error {
	errList := labels.ValidateLabelSelector(n.LabelSelector, labels.LabelSelectorValidationOptions{AllowInvalidLabelValueInSelector: false}, nil)
	if len(errList) > 0 {
		return fmt.Errorf("invalid label selector: %w", errList.ToAggregate())
	}

	if !n.SelectionExpression.IsZero() {
		if _, err := selector.Parse(string(n.SelectionExpression)); err != nil {
			return fmt.Errorf("invalid selectionExpression: %w", err)
		}
	}

	es := NewESFromK8sLabelSelector(labels.LabelSourceAnyKeyPrefix, n.LabelSelector)
	n.LabelSelector = es.LabelSelector
	n.cachedLabelSelectorString = buildSelectorKey(n.LabelSelector, n.SelectionExpression)

	return nil
}

// EndpointSelectorSlice is a slice of EndpointSelectors that can be sorted.
type EndpointSelectorSlice []EndpointSelector

func (s EndpointSelectorSlice) Len() int      { return len(s) }
func (s EndpointSelectorSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s EndpointSelectorSlice) Less(i, j int) bool {
	strI := s[i].LabelSelectorString()
	strJ := s[j].LabelSelectorString()

	return strings.Compare(strI, strJ) < 0
}

// SelectsAllEndpoints returns whether the EndpointSelectorSlice selects all
// endpoints, which is true if the wildcard endpoint selector is present in the
// slice.
func (s EndpointSelectorSlice) SelectsAllEndpoints() bool {
	for _, selector := range s {
		if selector.IsWildcard() {
			return true
		}
	}
	return false
}
