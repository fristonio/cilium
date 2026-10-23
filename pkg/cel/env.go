// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/interpreter"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/cel/library"
	ciliumceltypes "github.com/cilium/cilium/pkg/cel/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// EnvType represents the kind of CEL environment, which determines the
// variables and functions available for use in expressions.
type EnvType string

const (
	EnvTypeLabelSelector EnvType = "LabelSelector"
	EnvTypeFlowFilter    EnvType = "FlowFilter"
)

var (
	baseCELEnvOpts = []cel.EnvOption{
		cel.EagerlyValidateDeclarations(true),
		cel.HomogeneousAggregateLiterals(),
	}

	celEnvironments = map[EnvType][]cel.EnvOption{
		EnvTypeLabelSelector: {
			cel.OptionalTypes(),
			library.Labels(),
		},
		EnvTypeFlowFilter: {
			library.FlowFilter(),
		},
	}

	// Env is the global static CEL environment that can be used
	// to compile CEL expressions.
	Env Environment = nil
)

func init() {
	// Provide a usable environment before Hive replaces it with the configured
	// environment and metrics.
	env, err := NewEnvironment(DefaultConfig, nil)
	if err != nil {
		panic(fmt.Sprintf("Unable to create CEL environment: %s", err))
	}
	Env = env
}

var envInit sync.Once

func registerGlobalEnv(env Environment) {
	envInit.Do(func() {
		Env = env
	})
}

type Environment map[EnvType]*Compiler

func NewEnvironment(cfg Config, metrics *Metrics) (Environment, error) {
	env := make(map[EnvType]*Compiler)
	for kind, opts := range celEnvironments {
		compiler, err := NewCompiler(kind, cfg, metrics, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize compiler for env %s: %w", kind, err)
		}

		env[kind] = compiler
	}
	return env, nil
}

func (e Environment) Compile(kind EnvType, expression string) CompilationResult {
	c, ok := e[kind]
	if !ok {
		return CompilationResult{
			Error: fmt.Errorf("uninitialized environment %s", kind),
		}
	}
	return c.Compile(expression)
}

// CompilationResult is a compiled CEL expression ready for repeated evaluation.
// It is safe for concurrent use once created.
type CompilationResult struct {
	EnvType EnvType

	Expression string
	Program    cel.Program
	OutputType *cel.Type
	Error      error

	evaluationSuccess metric.Observer
	evaluationFailure metric.Observer
}

type singleVarActivation struct {
	name  string
	value any
}

var singleVarActivationPool = sync.Pool{New: func() any { return new(singleVarActivation) }}

func (a singleVarActivation) Parent() interpreter.Activation { return nil }

func (a singleVarActivation) ResolveName(name string) (any, bool) {
	if name != a.name {
		return nil, false
	}
	return a.value, true
}

// Evaluate evaluates the compiled expression against the provided value and returns whether
// the expression holds. Returns an error if the expression itself failed to
// compile or if evaluation produces a non-bool result.
func (r *CompilationResult) Evaluate(ctx context.Context, arg any) (match bool, evalErr error) {
	if r.Error != nil {
		return false, r.Error
	}

	// Derive activation for the CEL program based on the environment type.
	activation := singleVarActivationPool.Get().(*singleVarActivation)
	defer func() {
		activation.name = ""
		activation.value = nil
		singleVarActivationPool.Put(activation)
	}()
	if arg != nil {
		switch r.EnvType {
		case EnvTypeLabelSelector:
			lbls, ok := arg.(labels.Labels)
			if !ok {
				return false, fmt.Errorf("expected argument of type labels.Labels, got %T", arg)
			}
			activation.name = library.LabelsVarName
			activation.value = ciliumceltypes.NewLabelMap(lbls)
		case EnvTypeFlowFilter:
			flow, ok := arg.(*flowpb.Flow)
			if !ok {
				return false, fmt.Errorf("expected argument of type *flowpb.Flow, got %T", arg)
			}
			activation.name = library.FlowVarName
			activation.value = flow
		default:
			return false, fmt.Errorf("invalid environment %s", r.EnvType)
		}
	}

	if ctx == nil {
		return false, fmt.Errorf("context must not be nil")
	}

	var start time.Time
	if r.evaluationSuccess != nil {
		start = time.Now()
		defer func() {
			observer := r.evaluationSuccess
			if evalErr != nil {
				observer = r.evaluationFailure
			}
			observer.Observe(time.Since(start).Seconds())
		}()
	}

	var out ref.Val
	var err error
	if ctx.Done() == nil {
		out, _, err = r.Program.Eval(activation)
	} else {
		out, _, err = r.Program.ContextEval(ctx, activation)
	}
	if err != nil {
		return false, fmt.Errorf("CEL evaluation error: %w", err)
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression returned %T, expected bool", out.Value())
	}

	return b, nil
}
