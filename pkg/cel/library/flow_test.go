// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library_test

import (
	"testing"

	"cel.dev/cel-go/cel"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/cel/library"
)

func TestFlowFilter(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		flow       *flowpb.Flow
		want       bool
	}{
		{
			name:       "verdict",
			expression: "_flow.verdict == Verdict.FORWARDED",
			flow:       &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED},
			want:       true,
		},
		{
			name:       "IP address",
			expression: "_flow.IP.source == '10.0.0.1'",
			flow:       &flowpb.Flow{IP: &flowpb.IP{Source: "10.0.0.2"}},
			want:       false,
		},
		{
			name:       "TCP port",
			expression: "has(_flow.l4.TCP) && _flow.l4.TCP.destination_port == uint(443)",
			flow:       &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}}},
			want:       true,
		},
		{
			name:       "UDP is not TCP",
			expression: "has(_flow.l4.TCP)",
			flow:       &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 53}}}},
			want:       false,
		},
		{
			name:       "endpoint metadata",
			expression: "_flow.source.namespace == 'frontend' && _flow.destination.namespace == 'backend'",
			flow: &flowpb.Flow{
				Source:      &flowpb.Endpoint{Namespace: "frontend"},
				Destination: &flowpb.Endpoint{Namespace: "backend"},
			},
			want: true,
		},
	}

	env, err := cel.NewEnv(library.FlowFilter())
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.expression)
			if err := issues.Err(); err != nil {
				t.Fatal(err)
			}
			program, err := env.Program(ast)
			if err != nil {
				t.Fatal(err)
			}
			result, _, err := program.Eval(map[string]any{library.FlowVarName: tt.flow})
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := result.Value().(bool); !ok || got != tt.want {
				t.Fatalf("got %v, want %v", result.Value(), tt.want)
			}
		})
	}
}

func TestFlowFilterCompileError(t *testing.T) {
	env, err := cel.NewEnv(library.FlowFilter())
	if err != nil {
		t.Fatal(err)
	}
	_, issues := env.Compile("_flow.unknown == 0")
	if issues.Err() == nil {
		t.Fatal("expected compile error")
	}
}
