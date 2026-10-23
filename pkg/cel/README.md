# CEL runtime performance

Policy selector evaluation is a hot path. Identity labels are exposed as
`map<string, labels.Label>` through a zero-copy view backed by `labels.Labels`.
Label fields are available as `labels["app"].Source` and
`labels["app"].Value`; CEL adapts only labels read by the expression.

Direct map access performs a map lookup. Map comprehensions allocate iterator
state and scale with the number of labels, so direct access is preferable when
the key is known. `lookup()` is source-aware; for example,
`lookup("k8s:app").value().Value`. CIDR lookup may scan the label map.

`LabelMap.Iterator` snapshots the map keys. For 32 labels, an end-to-end
`labels.exists(...)` benchmark took about 8.0 microseconds, 4.9 KB, and 116
allocations. A lazy `reflect.MapIter` using a reusable `SetIterKey` took about
8.6 microseconds, 5.0 KB, and 128 allocations because converting each reflected
key to a CEL value adds allocations. `iter.Pull(maps.Keys(...))` was slower and
introduced coroutine and closure allocations. CEL's `Foldable` path can use a
direct Go map range, but is currently used only by two-variable comprehensions, not standard
one-variable expressions such as `labels.exists(key, ...)`. The key snapshot is
retained because it has the lowest total CPU and allocation cost.

Compiled programs are cached, including compilation failures. Evaluation uses a
pooled single-variable activation. Non-cancelable policy evaluation avoids CEL
context setup, while Hubble evaluation retains request cancellation. Runtime
cost tracking remains enabled by default to bound user expressions.

## Runtime cost tracking overhead

`BenchmarkRuntimeCostTracking` compares complete `CompilationResult.Evaluate`
calls with the runtime cost tracker and limit enabled and disabled. Six runs on
Linux/arm64 with `GOMAXPROCS=6` produced these medians:

| Expression shape | Disabled | Enabled | CPU increase | Disabled / enabled allocations |
| --- | ---: | ---: | ---: | ---: |
| Direct label access | 151 ns | 572 ns | 279% | 4 / 12 |
| Source-aware `lookup()` | 680 ns | 1.33 us | 95% | 11 / 25 |
| 32-label full comprehension | 8.70 us | 26.96 us | 210% | 226 / 459 |
| Scalar Flow field | 183 ns | 764 ns | 318% | 0 / 9 |
| 32-name Flow comprehension | 3.92 us | 18.46 us | 371% | 100 / 303 |

The cost tracker instruments CEL evaluation nodes and clones tracker state for
each evaluation. This work dominates the cost of small expressions and adds
per-iteration work to comprehensions.

Runtime tracking can be omitted for a program when its compile-time maximum is
finite, is within the runtime budget, and every input bound used by the static
estimate is enforced. Compile-time estimation happens once, outside the hot
path. A program with an unknown maximum must retain runtime tracking or be
rejected during compilation. Label-map cardinality and Flow protobuf field
bounds are not fully enforced yet, so runtime tracking cannot currently be
disabled for all programs safely.

Run the relevant benchmarks with:

```shell
go test ./pkg/cel ./pkg/policy/types ./pkg/hubble/filters -run '^$' -bench 'CEL|LabelSelectorEvaluation' -benchmem
```

To reproduce the runtime cost comparison and summarize repeated samples:

```shell
go test ./pkg/cel -run '^$' -bench '^BenchmarkRuntimeCostTracking$' -benchmem -count=6 > runtime-cost.txt
benchstat -col /runtime_cost runtime-cost.txt
```

See [Hubble Flow CEL cost bounds](HUBBLE_FLOW_COST_BOUNDS.md) for the current
compile-time behavior and the plan for descriptor-backed protobuf field bounds.
