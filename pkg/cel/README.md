# CEL cost enforcement and performance

Policy selector evaluation is a hot path. Identity labels are exposed as
`map<string, labels.Label>` through a zero-copy view backed by `labels.Labels`.
Expressions can read fields directly, for example `labels["app"].Source` and
`labels["app"].Value`. `lookup("k8s:app")` also performs a source-aware lookup.

## Label selectors

Label selectors use compile-time cost enforcement and do not enable cel-go's
runtime cost tracker when `cel-expression-max-cost` is enabled. The compiler
accepts an expression only when its static estimate is within that limit.

`labels.Labels` has no cardinality limit. Operations whose cost depends on the
number of labels therefore have no finite static maximum and are rejected.
This includes map comprehensions, dynamic `lookup()` keys, and CIDR lookups,
which may scan the map. Direct map access and `lookup()` with a literal,
non-CIDR key have finite bounds.

Label strings also have no enforced size limit, so operations whose cost scales
with string length, such as `size()`, `contains()`, and `matches()`, are rejected
by the default static limit. The estimator does not assume unenforced string
bounds.

Setting `cel-expression-max-cost` to zero disables static admission and makes
label selectors use `cel-program-max-cost` instead. Setting both to zero
disables both checks.

## Runtime cost tracking measurements

Before removing runtime tracking from label selectors,
`BenchmarkRuntimeCostTracking` measured complete evaluation calls with tracking
enabled and disabled. Six runs on Linux/arm64 with `GOMAXPROCS=6` produced these
medians:

| Expression shape | Disabled | Enabled | CPU increase | Disabled / enabled allocations |
| --- | ---: | ---: | ---: | ---: |
| Direct label access | 151 ns | 572 ns | 279% | 4 / 12 |
| Source-aware `lookup()` | 680 ns | 1.33 us | 95% | 11 / 25 |
| 32-label full comprehension | 8.70 us | 26.96 us | 210% | 226 / 459 |
| Scalar Flow field | 183 ns | 764 ns | 318% | 0 / 9 |
| 32-name Flow comprehension | 3.92 us | 18.46 us | 371% | 100 / 303 |

The cost tracker instruments evaluation nodes and clones tracker state for each
evaluation. It adds a large fixed cost to small expressions and per-iteration
work to comprehensions. Label selectors avoid this work after their static cost
is accepted. Hubble Flow expressions retain runtime tracking because Flow
protobuf fields do not yet have enforced size bounds.

The current benchmarks cover production label evaluation and runtime tracking
comparisons for labels and Flow:

```shell
go test ./pkg/cel ./pkg/policy/types ./pkg/hubble/filters -run '^$' -bench 'CEL|LabelSelectorEvaluation' -benchmem
go test ./pkg/cel -run '^$' -bench '^BenchmarkRuntimeCostTracking$' -benchmem -count=6 > runtime-cost.txt
benchstat -col /runtime_cost runtime-cost.txt
```

The relevant test suites are run with:

```shell
go test ./pkg/cel/... ./pkg/policy/api ./pkg/policy/types ./pkg/policy ./pkg/hubble/filters
```

See [Hubble Flow CEL cost bounds](HUBBLE_FLOW_COST_BOUNDS.md) for the plan to
derive Flow size bounds from protobuf validation annotations.
