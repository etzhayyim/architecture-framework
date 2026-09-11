(ns etzhayyim.architecture-framework.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [etzhayyim.architecture-framework.core :as eaf]))

(defn ep [target role]
  {:endpoint/incidence target
   :endpoint/role role
   :endpoint/sign 1
   :endpoint/multiplicity 1})

(defn node
  ([id kind] (node id kind [] {}))
  ([id kind boundary] (node id kind boundary {}))
  ([id kind boundary observables]
   {:incidence/id id
    :incidence/kind kind
    :incidence/boundary (vec boundary)
    :incidence/observables observables}))

(defn structural-architecture [prefix]
  (let [anchor (keyword (str prefix "-person"))
        body (keyword (str prefix "-body"))
        history (keyword (str prefix "-history"))]
    {:eaf/version 1
     :eaf/basis "bafy-basis-1"
     :eaf/incidences
     {anchor (node anchor :eaf/individual-anchor
                   [(ep body :constitution/body)
                    (ep history :constitution/history)])
      body (node body :eaf/constitution)
      history (node history :eaf/constitution)}}))

(deftest individual-is-incidence-structure-not-raw-id
  (let [left-arch (structural-architecture "left")
        right-arch (structural-architecture "right")
        left (eaf/individual left-arch
                             {:individual/anchor :left-person
                              :individual/scope {:scope/max-depth 4}})
        right (eaf/individual right-arch
                              {:individual/anchor :right-person
                               :individual/scope {:scope/max-depth 4}})]
    (is (not= (:individual/anchor left) (:individual/anchor right)))
    (is (= (:individual/signature left) (:individual/signature right)))
    (is (eaf/same-individual? left right))))

(deftest cross-basis-continuity-is-not-inferred
  (let [arch (structural-architecture "x")
        individual (eaf/individual arch {:individual/anchor :x-person})
        later (assoc individual :individual/basis "bafy-basis-2")]
    (is (not (eaf/same-individual? individual later)))))

(defn trust-architecture [effectful?]
  (let [base (structural-architecture "alice")
        more
        {:controller (node :controller :eaf/individual-anchor
                           [(ep :controller-key :constitution/key)])
         :controller-key (node :controller-key :eaf/constitution)
         :vm (node :vm :eaf/verification-method)
         :did-binding
         (node :did-binding :eaf/identifier-binding
               [(ep :alice-person :identifier/subject)
                (ep :controller :identifier/controller)
                (ep :vm :identifier/verification-method)]
               {:identifier/value "did:etzhayyim:bafyexample"})
         :challenge (node :challenge :eaf/challenge)
         :proof (node :proof :eaf/proof)
         :authn
         (node :authn :eaf/authentication
               [(ep :alice-person :authentication/subject)
                (ep :challenge :authentication/challenge)
                (ep :proof :authentication/proof)]
               {:authentication/purpose :login
                :authentication/audience "kotoba://runtime"
                :authentication/nonce "n-1"
                :authentication/fresh-until "2026-08-12T04:00:00Z"})
         :principal
         (node :principal :eaf/session-principal
               [(ep :alice-person :principal/individual)
                (ep :authn :principal/authentication)])
         :capability (node :capability :eaf/capability)
         :resource (node :resource :eaf/resource)
         :authority
         (node :authority :eaf/authorization
               [(ep :principal :authorization/principal)
                (ep :capability :authorization/capability)
                (ep :resource :authorization/resource)]
               {:authorization/constraints {:uses 1}})
         :execution
         (node :execution :eaf/execution
               (if effectful?
                 [(ep :alice-person :execution/individual)
                  (ep :authn :execution/authentication)
                  (ep :authority :execution/authority)]
                 [])
               {:execution/effectful? effectful?
                :execution/artifact "bafy-artifact"
                :execution/policy "bafy-policy"
                :execution/input "bafy-input"})}]
    (update base :eaf/incidences merge more)))

(deftest trust-concepts-remain-separate
  (let [architecture (trust-architecture true)]
    (is (eaf/conformant? architecture))
    (is (= #{:did-binding :vm :challenge :proof :authn :principal :authority}
           (set (keys (:eaf/incidences (eaf/project-view architecture :tv))))))))

(deftest effectful-execution-requires-authentication-and-authority
  (let [architecture (trust-architecture true)
        broken (update-in architecture [:eaf/incidences :execution :incidence/boundary]
                          #(vec (remove (fn [endpoint]
                                         (= :execution/authority
                                            (:endpoint/role endpoint))) %)))]
    (is (some #(= :incidence/role-cardinality (:eaf.problem/code %))
              (eaf/conformance-problems broken)))
    (is (eaf/conformant? (trust-architecture false)))))

(deftest dangling-endpoints-fail-closed
  (let [architecture (update-in (structural-architecture "bad")
                                [:eaf/incidences :bad-person :incidence/boundary]
                                conj (ep :absent :constitution/missing))]
    (is (= :endpoint/dangling
           (:eaf.problem/code (first (eaf/architecture-problems architecture)))))))

(deftest views-share-one-basis-and-are-deterministic
  (let [architecture (trust-architecture true)
        first-view (eaf/project-view architecture :iv)
        second-view (eaf/project-view architecture :iv)]
    (is (= first-view second-view))
    (is (= (:eaf/basis architecture) (:eaf/basis first-view)))
    (is (= #{:alice-person :alice-body :alice-history :controller :controller-key}
           (set (keys (:eaf/incidences first-view)))))))
