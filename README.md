# Etzhayyim Architecture Framework

EAF is an incidence-first, data-centric architecture framework. It applies the
fit-for-purpose view discipline of DoDAF 2.02 to one canonical incidence graph,
while replacing entity-first identity with a checked construction:

```text
individual = bisimulation quotient(incidence closure, scope, immutable basis)
```

An ID only locates an incidence. A DID is an identifier binding to an
individual; it is not the individual. Authentication is a challenge-proof
occurrence, authorization is a constrained principal-capability-resource
incidence, and an execution binds those facts to an artifact, policy, input,
and receipts.

## What R0 implements

- a portable `.cljc` incidence graph model;
- structural validation of boundaries, roles, signs, and multiplicities;
- finite closure and deterministic bisimulation partition refinement;
- individual signatures independent of raw incidence IDs;
- explicit DID-binding/authentication/authorization/execution separation;
- fail-closed admission rules for effectful execution; and
- AV, IV, TV, CV, OV, ExV, DIV, PV, and StdV projections from one basis.

The shared vocabulary is in [`resources/eaf/ontology.edn`](resources/eaf/ontology.edn).

## Example

```clojure
(require '[etzhayyim.architecture-framework.core :as eaf])

(def architecture
  {:eaf/version 1
   :eaf/basis "bafy..."
   :eaf/incidences
   {:alice {:incidence/id :alice
            :incidence/kind :eaf/individual-anchor
            :incidence/boundary
            [{:endpoint/incidence :history
              :endpoint/role :constitution/history
              :endpoint/sign 1
              :endpoint/multiplicity 1}]}
    :history {:incidence/id :history
              :incidence/kind :eaf/constitution
              :incidence/boundary []}}})

(eaf/individual architecture {:individual/anchor :alice})
(eaf/project-view architecture :iv)
```

## Conformance boundary

R0 validates internal architecture data. It does not resolve a DID, verify a
signature, prove that a basis string is a CID, or grant a host capability.
Those are injected trust boundaries. Kotoba should require the resulting EAF
authentication and authorization incidences for effectful production runs;
pure computation may remain anonymous.

Cross-basis identity is never inferred. Continuity requires an explicit
`:eaf/persistence` incidence such as `continues`, `splits`, `merges`, or
`supersedes`, plus the invariants required by the consuming policy.

## Verify

```bash
clojure -M:test
```

## Sources

- [Theory of Incidence](https://github.com/com-junkawasaki/inc)
- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/)
- [DoDAF 2.02](https://dodcio.defense.gov/DoDAF/)

Licensed under Apache-2.0.
