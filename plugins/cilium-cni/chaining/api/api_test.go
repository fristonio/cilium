// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"testing"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/plugins/cilium-cni/lib"
)

type pluginTest struct{}

func (p *pluginTest) Add(ctx context.Context, pluginContext PluginContext, client lib.CiliumCniClient) (res *cniTypesVer.Result, err error) {
	return nil, nil
}

func (p *pluginTest) Delete(ctx context.Context, pluginContext PluginContext, client lib.CiliumCniClient) (err error) {
	return nil
}

func (p *pluginTest) Check(ctx context.Context, pluginContext PluginContext, client lib.CiliumCniClient) error {
	return nil
}

func (p *pluginTest) Status(ctx context.Context, pluginContext PluginContext, client lib.CiliumCniClient) error {
	return nil
}

func TestRegistration(t *testing.T) {
	err := Register("foo", &pluginTest{})
	require.NoError(t, err)

	err = Register("foo", &pluginTest{})
	require.Error(t, err)

	err = Register(DefaultConfigName, &pluginTest{})
	require.Error(t, err)
}

func TestNonChaining(t *testing.T) {
	require.Nil(t, Lookup("cilium"))
}
