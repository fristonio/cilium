// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"reflect"

	celtypes "cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"

	"github.com/cilium/cilium/pkg/labels"
)

// NativeLabelType describes labels.Label to CEL.
var NativeLabelType = mustNativeLabelType()

func mustNativeLabelType() *celtypes.NativeType {
	t, err := celtypes.NewNativeType(reflect.TypeFor[labels.Label]())
	if err != nil {
		panic(err)
	}
	return t
}

// LabelMap is a zero-copy CEL view backed by labels.Labels.
type LabelMap struct {
	labels.Labels
}

func NewLabelMap(lbls labels.Labels) LabelMap {
	return LabelMap{Labels: lbls}
}

func (m LabelMap) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeFor[labels.Labels]().AssignableTo(typeDesc) {
		return m.Labels, nil
	}
	return nil, fmt.Errorf("type conversion error from labels to %v", typeDesc)
}

func (m LabelMap) ConvertToType(typeVal ref.Type) ref.Val {
	if typeVal == celtypes.MapType {
		return m
	}
	if typeVal == celtypes.TypeType {
		return celtypes.MapType
	}
	return celtypes.NewErr("type conversion error from labels to %s", typeVal)
}

func (m LabelMap) Equal(other ref.Val) ref.Val {
	o, ok := other.(traits.Mapper)
	if !ok || m.Size() != o.Size() {
		return celtypes.False
	}
	for key := range m.Labels {
		value, _ := m.Find(celtypes.String(key))
		otherValue, found := o.Find(celtypes.String(key))
		if !found || value.Equal(otherValue) != celtypes.True {
			return celtypes.False
		}
	}
	return celtypes.True
}

func (LabelMap) Type() ref.Type  { return celtypes.MapType }
func (m LabelMap) Value() any    { return m.Labels }
func (m LabelMap) Size() ref.Val { return celtypes.Int(len(m.Labels)) }

func (m LabelMap) Find(key ref.Val) (ref.Val, bool) {
	k, ok := key.Value().(string)
	if !ok {
		return celtypes.NewErr("labels map key must be string, got %T", key.Value()), false
	}
	lbl, found := m.Labels[k]
	if !found {
		return nil, false
	}
	return NativeLabelType.Adapt(celtypes.DefaultTypeAdapter, lbl), true
}

func (m LabelMap) Get(index ref.Val) ref.Val {
	value, found := m.Find(index)
	if !found {
		return celtypes.NewErr("no such key: %v", index)
	}
	return value
}

func (m LabelMap) Contains(value ref.Val) ref.Val {
	_, found := m.Find(value)
	return celtypes.Bool(found)
}

func (m LabelMap) Iterator() traits.Iterator {
	keys := make([]string, 0, len(m.Labels))
	for key := range m.Labels {
		keys = append(keys, key)
	}
	return &labelMapIterator{keys: keys}
}

type labelMapIterator struct {
	keys  []string
	index int
}

func (*labelMapIterator) ConvertToNative(reflect.Type) (any, error) {
	return nil, fmt.Errorf("iterator conversion is not supported")
}
func (i *labelMapIterator) ConvertToType(ref.Type) ref.Val {
	return celtypes.NewErr("no such overload")
}
func (i *labelMapIterator) Equal(ref.Val) ref.Val { return celtypes.NewErr("no such overload") }
func (*labelMapIterator) Type() ref.Type          { return celtypes.IteratorType }
func (*labelMapIterator) Value() any              { return nil }
func (i *labelMapIterator) HasNext() ref.Val      { return celtypes.Bool(i.index < len(i.keys)) }
func (i *labelMapIterator) Next() ref.Val {
	if i.index >= len(i.keys) {
		return celtypes.NewErr("iterator exhausted")
	}
	key := i.keys[i.index]
	i.index++
	return celtypes.String(key)
}
