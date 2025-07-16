// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/halo/cmd"
	"github.com/cilium/cilium/pkg/hive"
)

func main() {
	operatorHive := hive.New(cmd.Halo)

	cmd.Execute(cmd.NewHaloCmd(operatorHive))
}
