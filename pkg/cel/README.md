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

Run the relevant benchmarks with:

```shell
go test ./pkg/cel ./pkg/policy/types ./pkg/hubble/filters -run '^$' -bench 'CEL|LabelSelectorEvaluation' -benchmem
```
