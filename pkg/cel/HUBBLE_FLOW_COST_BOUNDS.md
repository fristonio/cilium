# Hubble Flow CEL cost bounds

Hubble Flow CEL expressions use `_flow`, whose type is the `flow.Flow`
protobuf. CEL can determine the cost of fixed-size operations, but it needs
application-provided size bounds for variable-length protobuf fields such as
strings, bytes, and repeated fields.

## Current behavior

An unknown input size is not estimated as zero. cel-go represents it with an
unknown or extremely large maximum. The exact result depends on how the size
is used by the expression. With the default compile-time limit of 10,000, the
current branch produces these estimates:

| Expression | Estimated cost | Admitted |
| --- | ---: | --- |
| `_flow.verdict == Verdict.FORWARDED` | 4..4 | yes |
| `_flow.source.identity == 123u` | 4..4 | yes |
| `_flow.source.namespace == "default"` | 4..4 | yes |
| `_flow.source.namespace.contains("prod")` | 3..1844674407370955267 | no |
| `_flow.source_names.size() > 0` | 4..4 | yes |
| `_flow.source_names.exists(n, n == "frontend")` | 3..`math.MaxUint64` | yes |
| `_flow.source_names.exists(n, n.contains("front"))` | 3..`math.MaxUint64` | yes |
| `_flow.l7.http.headers.exists(h, h.key == "x-user")` | 5..`math.MaxUint64` | yes |

The last three expressions are admitted because the compiler currently checks
only the minimum when the maximum is exactly `math.MaxUint64`. They therefore
do not receive effective worst-case compile-time enforcement. Runtime cost
tracking remains enabled and stops an evaluation that exceeds its runtime
budget.

The Cilium cost estimator currently supplies identity-label bounds and custom
`lookup()` costs. It does not supply bounds for fields reachable from
`flow.Flow`.

## Proposed design

Use Protovalidate field annotations in `flow.proto` to describe upper bounds:

- `string.max_len` or `string.max_bytes` for strings;
- `bytes.max_len` for bytes;
- `repeated.max_items` and item rules for repeated fields;
- `map.max_pairs` and key/value rules for maps.

Protovalidate is the maintained successor to `protoc-gen-validate`. Cilium's
Envoy API uses the older `validate.rules` annotations, but
`protoc-gen-validate` is archived. The existing `protoc` generation workflow
can use Protovalidate annotations without adopting the Buf CLI or placing the
Protovalidate runtime in the flow evaluation path.

cel-go does not interpret either validation annotation format automatically.
At CEL environment initialization, build an immutable size table from the
`flow.Flow` descriptor and its annotations. A Flow cost estimator can then
resolve CEL paths such as:

- `_flow.source.labels` and `_flow.source.labels.@items`;
- `_flow.source.workloads` and nested workload fields;
- `_flow.l7.http.headers` and nested header key/value fields.

Descriptor processing occurs outside expression evaluation and must not add
work or allocations to the flow-matching hot path.

When bounded-cost enforcement is enabled for the Flow environment, reject an
expression if a variable-cost operation still depends on an unknown size.
Keep runtime cost tracking as protection against incorrect bounds or invariant
violations.

Runtime tracking has measurable CPU and allocation overhead, especially for
small expressions and comprehensions. Once the static maximum is finite and
all contributing bounds are enforced, runtime tracking is redundant for that
program and can be omitted. Programs with an unknown maximum must retain it or
fail compilation. Benchmark results and reproduction commands are recorded in
the package README.

## Bound soundness

Annotations describe constraints but do not enforce them on Go protobuf
values. A static upper bound is sound only when every Flow value evaluated by
CEL satisfies the same constraint.

For each variable-size field:

1. Identify its producer and any existing protocol or source limit.
2. Use that existing limit as the annotation where possible.
3. If no limit exists, enforce one while constructing or accepting the Flow
   rather than traversing and validating the complete Flow for every CEL
   evaluation.
4. Define how an oversized value is handled. Silent truncation can change
   filter semantics and should not be the default.

`google.protobuf.Any extensions` cannot provide general bounds for arbitrary
embedded messages. Variable-cost expressions over unbounded extension content
should fail bounded-cost admission. Fixed-cost operations that do not require
the content size can remain available.

The number and length of `FlowFilter.Experimental.cel_expression` entries also
need admission bounds. Per-expression parser limits do not bound the total
number of expressions submitted in one filter.

## Compatibility

Validation annotations do not change protobuf field numbers, wire types, JSON
names, or generated Flow struct fields. Existing generated clients continue to
interoperate and ignore unknown descriptor options. Consumers regenerating the
Hubble API from source will need the Protovalidate schema in their protobuf
include path.

Enforcing a new maximum is a semantic change for producers that can currently
create larger values. Bounded-cost admission can also reject experimental CEL
expressions that were previously accepted with an unknown worst-case cost.
Compilation errors should identify the unbounded field path.

## Implementation and validation plan

1. Inventory every variable-sized field reachable from `flow.Flow` and record
   its source, bound, and enforcement point. The current schema has 79 such
   reachable paths when repeated nested occurrences are counted.
2. Add annotations and update protobuf generation dependencies.
3. Enforce any missing bounds at producer or external-ingress boundaries.
4. Add a descriptor-backed Flow size estimator and compose it with the
   existing Cilium estimator.
5. Make the Flow compiler fail closed when a required maximum remains unknown.
6. Add a schema coverage test requiring each reachable variable-sized field to
   be bounded or explicitly excluded.
7. Test scalar strings, repeated strings, repeated messages, nested item
   fields, and static-versus-runtime cost agreement at declared bounds.
8. Benchmark Hubble CEL evaluation before and after the change. Evaluation
   time and allocations should remain unchanged; separately benchmark any
   producer-side enforcement.

Relevant upstream references:

- [cel-go cost estimation](https://github.com/cel-go/cel-go/tree/main/checker)
- [Protovalidate](https://github.com/bufbuild/protovalidate)
- [Protovalidate Go](https://github.com/bufbuild/protovalidate-go)
- [Archived protoc-gen-validate](https://github.com/bufbuild/protoc-gen-validate)
