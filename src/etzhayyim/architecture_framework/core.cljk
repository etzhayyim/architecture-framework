(ns etzhayyim.architecture-framework.core
  "Incidence-first architecture data, individual construction, and views.

  IDs locate incidences. They do not establish individual equality. An
  individual is the bisimulation quotient of a scoped incidence closure at an
  immutable basis. DID bindings, authentication, authorization, and execution
  remain distinct incidences."
  )

(def viewpoints
  {:av #{:eaf/context :eaf/decision :eaf/term :eaf/provenance}
   :iv #{:eaf/individual-anchor :eaf/constitution :eaf/persistence}
   :tv #{:eaf/identifier-binding :eaf/verification-method :eaf/challenge
         :eaf/proof :eaf/authentication :eaf/session-principal
         :eaf/authorization :eaf/revocation}
   :cv #{:eaf/capability :eaf/resource :eaf/authorization}
   :ov #{:eaf/activity :eaf/interaction :eaf/resonance :eaf/responsibility}
   :exv #{:eaf/execution :eaf/artifact :eaf/policy :eaf/receipt}
   :div #{:eaf/schema :eaf/encoding :eaf/information :eaf/datum}
   :pv #{:eaf/persistence :eaf/change :eaf/project}
   :stdv #{:eaf/standard :eaf/profile :eaf/conformance-rule}})

(def allowed-signs #{-1 0 1})

(defn- stable-sort [xs]
  (sort-by pr-str xs))

(defn- endpoint-target [endpoint]
  (:endpoint/incidence endpoint))

(defn- endpoint-label [endpoint]
  [(:endpoint/role endpoint)
   (:endpoint/sign endpoint)
   (:endpoint/multiplicity endpoint)])

(defn architecture-problems
  "Return structural problems. An empty vector is a valid finite incidence
  architecture. The immutable basis is deliberately supplied by the caller;
  this library does not pretend that an arbitrary string is a verified CID."
  [{:eaf/keys [basis incidences]}]
  (let [ids (set (keys incidences))]
    (vec
     (concat
      (when-not (and (string? basis) (seq basis))
        [{:eaf.problem/code :basis/required}])
      (when-not (map? incidences)
        [{:eaf.problem/code :incidences/map-required}])
      (mapcat
       (fn [[id incidence]]
         (let [boundary (:incidence/boundary incidence)]
           (concat
            (when-not (= id (:incidence/id incidence))
              [{:eaf.problem/code :incidence/id-mismatch
                :incidence/key id
                :incidence/id (:incidence/id incidence)}])
            (when-not (keyword? (:incidence/kind incidence))
              [{:eaf.problem/code :incidence/kind-required
                :incidence/id id}])
            (when-not (vector? boundary)
              [{:eaf.problem/code :incidence/boundary-vector-required
                :incidence/id id}])
            (mapcat
             (fn [endpoint]
               (let [target (endpoint-target endpoint)
                     multiplicity (:endpoint/multiplicity endpoint)]
                 (concat
                  (when-not (contains? ids target)
                    [{:eaf.problem/code :endpoint/dangling
                      :incidence/id id :endpoint/target target}])
                  (when (= id target)
                    [{:eaf.problem/code :endpoint/direct-self-reference
                      :incidence/id id}])
                  (when-not (keyword? (:endpoint/role endpoint))
                    [{:eaf.problem/code :endpoint/role-required
                      :incidence/id id :endpoint endpoint}])
                  (when-not (contains? allowed-signs (:endpoint/sign endpoint))
                    [{:eaf.problem/code :endpoint/sign-invalid
                      :incidence/id id :endpoint endpoint}])
                  (when-not (and (integer? multiplicity) (pos? multiplicity))
                    [{:eaf.problem/code :endpoint/multiplicity-invalid
                      :incidence/id id :endpoint endpoint}]))))
             (if (vector? boundary) boundary [])))))
       (if (map? incidences) incidences {}))))))

(defn valid-architecture? [architecture]
  (empty? (architecture-problems architecture)))

(defn- selected-endpoints [incidence roles]
  (filter #(or (nil? roles) (contains? roles (:endpoint/role %)))
          (:incidence/boundary incidence)))

(defn incidence-closure
  "Return the finite incidence closure rooted at anchor. Scope accepts
  :scope/roles and :scope/max-depth. A nil roles set follows every role."
  [{:eaf/keys [incidences] :as architecture}
   {:individual/keys [anchor scope]}]
  (when-let [problems (seq (architecture-problems architecture))]
    (throw (ex-info "invalid EAF architecture" {:eaf/problems problems})))
  (when-not (contains? incidences anchor)
    (throw (ex-info "individual anchor is absent"
                    {:eaf.problem/code :individual/anchor-absent
                     :individual/anchor anchor})))
  (let [roles (:scope/roles scope)
        max-depth (get scope :scope/max-depth (count incidences))]
    (when-not (and (integer? max-depth) (not (neg? max-depth)))
      (throw (ex-info "scope max depth must be a non-negative integer"
                      {:eaf.problem/code :individual/scope-depth-invalid})))
    (loop [queue (conj #?(:clj clojure.lang.PersistentQueue/EMPTY
                          :cljs cljs.core/PersistentQueue.EMPTY)
                       [anchor 0])
           depths {anchor 0}]
      (if (empty? queue)
        (set (keys depths))
        (let [[[id depth] queue'] [(peek queue) (pop queue)]
              targets (if (< depth max-depth)
                        (map endpoint-target
                             (selected-endpoints (get incidences id) roles))
                        [])
              unseen (remove #(contains? depths %) targets)]
          (recur (into queue' (map #(vector % (inc depth)) unseen))
                 (reduce #(assoc %1 %2 (inc depth)) depths unseen)))))))

(defn- observable [incidence]
  [(:incidence/kind incidence)
   (or (:incidence/observables incidence) {})])

(defn- assign-colors [signatures]
  (let [ordered (vec (stable-sort (distinct (vals signatures))))
        color-of (zipmap ordered (range))]
    (into {} (map (fn [[id signature]] [id (color-of signature)]) signatures))))

(defn- refinement-signature [incidences members colors roles id]
  (let [incidence (get incidences id)]
    [(observable incidence)
     (vec
      (stable-sort
       (map (fn [endpoint]
              (let [target (endpoint-target endpoint)]
                [(endpoint-label endpoint)
                 (if (contains? members target)
                   [:class (colors target)]
                   [:outside (observable (get incidences target))])]))
            (selected-endpoints incidence roles))))]))

(defn bisimulation-partition
  "Compute the coarsest stable observational partition of a scoped finite
  incidence closure. Returned color numbers are deterministic and independent
  of raw incidence IDs."
  [{:eaf/keys [incidences] :as architecture} individual]
  (let [members (incidence-closure architecture individual)
        roles (get-in individual [:individual/scope :scope/roles])
        initial (assign-colors
                 (into {} (map (fn [id] [id (observable (get incidences id))])
                               members)))]
    (loop [colors initial
           remaining (inc (count members))]
      (let [next-colors
            (assign-colors
             (into {} (map (fn [id]
                             [id (refinement-signature incidences members colors roles id)])
                           members)))]
        (cond
          (= colors next-colors) colors
          (zero? remaining)
          (throw (ex-info "incidence partition did not stabilize"
                          {:eaf.problem/code :individual/partition-unstable}))
          :else (recur next-colors (dec remaining)))))))

(defn individual
  "Construct an individual as a basis-scoped bisimulation quotient. The
  signature, not :individual/anchor, is its structural identity."
  [{:eaf/keys [basis incidences] :as architecture} individual-spec]
  (let [members (incidence-closure architecture individual-spec)
        colors (bisimulation-partition architecture individual-spec)
        roles (get-in individual-spec [:individual/scope :scope/roles])
        by-color (group-by colors members)
        quotient
        (->> by-color
             (map (fn [[color ids]]
                    (let [representative (first (stable-sort ids))]
                      [color
                       (refinement-signature incidences members colors roles representative)
                       (count ids)])))
             stable-sort
             vec)]
    {:individual/basis basis
     :individual/anchor (:individual/anchor individual-spec)
     :individual/anchor-class (colors (:individual/anchor individual-spec))
     :individual/members (vec (stable-sort members))
     :individual/signature
     {:eaf.signature/version 1
      :individual/anchor-class (colors (:individual/anchor individual-spec))
      :individual/quotient quotient}}))

(defn same-individual?
  "Structural equality at the declared bases. Cross-basis continuity must be
  represented by an explicit :eaf/persistence incidence and is never inferred."
  [left right]
  (and (= (:individual/basis left) (:individual/basis right))
       (= (:individual/signature left) (:individual/signature right))))

(defn- targets-for-role [incidence role]
  (->> (:incidence/boundary incidence)
       (filter #(= role (:endpoint/role %)))
       (map endpoint-target)
       set))

(defn- exactly-one-role-problems [id incidence role]
  (when-not (= 1 (count (targets-for-role incidence role)))
    [{:eaf.problem/code :incidence/role-cardinality
      :incidence/id id :endpoint/role role :expected 1}]))

(defn- target-kind? [incidences incidence role kind]
  (let [targets (targets-for-role incidence role)]
    (and (seq targets)
         (every? #(= kind (:incidence/kind (get incidences %))) targets))))

(defn- target-kind-problems [incidences id incidence role kind]
  (when (and (seq (targets-for-role incidence role))
             (not (target-kind? incidences incidence role kind)))
    [{:eaf.problem/code :incidence/role-target-kind
      :incidence/id id
      :endpoint/role role
      :expected-kind kind}]))

(defn conformance-problems
  "Validate the EAF trust and execution separation rules in addition to the
  generic incidence shape."
  [{:eaf/keys [incidences] :as architecture}]
  (vec
   (concat
    (architecture-problems architecture)
    (mapcat
     (fn [[id incidence]]
       (let [kind (:incidence/kind incidence)
             observables (:incidence/observables incidence)]
         (case kind
           :eaf/individual-anchor
           (when-not (seq (:incidence/boundary incidence))
             [{:eaf.problem/code :individual/not-incidence-constructed
               :incidence/id id}])

           :eaf/identifier-binding
           (concat
           (mapcat #(exactly-one-role-problems id incidence %)
                    [:identifier/subject :identifier/controller
                     :identifier/verification-method])
            (target-kind-problems incidences id incidence
                                  :identifier/subject :eaf/individual-anchor)
            (target-kind-problems incidences id incidence
                                  :identifier/controller :eaf/individual-anchor)
            (target-kind-problems incidences id incidence
                                  :identifier/verification-method
                                  :eaf/verification-method)
            (when-not (and (string? (:identifier/value observables))
                           (seq (:identifier/value observables)))
              [{:eaf.problem/code :identifier/value-required
                :incidence/id id}]))

           :eaf/authentication
           (concat
            (mapcat #(exactly-one-role-problems id incidence %)
                    [:authentication/subject :authentication/challenge
                     :authentication/proof])
            (target-kind-problems incidences id incidence
                                  :authentication/subject :eaf/individual-anchor)
            (target-kind-problems incidences id incidence
                                  :authentication/challenge :eaf/challenge)
            (target-kind-problems incidences id incidence
                                  :authentication/proof :eaf/proof)
            (for [key [:authentication/purpose :authentication/audience
                       :authentication/nonce :authentication/fresh-until]
                  :when (nil? (get observables key))]
              {:eaf.problem/code :authentication/observable-required
               :incidence/id id :observable/key key}))

           :eaf/session-principal
           (concat
            (mapcat #(exactly-one-role-problems id incidence %)
                    [:principal/individual :principal/authentication])
            (target-kind-problems incidences id incidence
                                  :principal/individual :eaf/individual-anchor)
            (target-kind-problems incidences id incidence
                                  :principal/authentication :eaf/authentication))

           :eaf/authorization
           (concat
            (mapcat #(exactly-one-role-problems id incidence %)
                    [:authorization/principal :authorization/capability
                     :authorization/resource])
            (target-kind-problems incidences id incidence
                                  :authorization/principal :eaf/session-principal)
            (target-kind-problems incidences id incidence
                                  :authorization/capability :eaf/capability)
            (target-kind-problems incidences id incidence
                                  :authorization/resource :eaf/resource)
            (when-not (map? (:authorization/constraints observables))
              [{:eaf.problem/code :authorization/constraints-required
                :incidence/id id}]))

           :eaf/execution
           (when (:execution/effectful? observables)
             (concat
              (mapcat #(exactly-one-role-problems id incidence %)
                      [:execution/individual :execution/authentication
                       :execution/authority])
              (target-kind-problems incidences id incidence
                                    :execution/individual :eaf/individual-anchor)
              (target-kind-problems incidences id incidence
                                    :execution/authentication :eaf/authentication)
              (target-kind-problems incidences id incidence
                                    :execution/authority :eaf/authorization)
              (for [key [:execution/artifact :execution/policy :execution/input]
                    :when (nil? (get observables key))]
                {:eaf.problem/code :execution/observable-required
                 :incidence/id id :observable/key key})))

           nil)))
     (if (map? incidences) incidences {})))))

(defn conformant? [architecture]
  (empty? (conformance-problems architecture)))

(defn project-view
  "Project one DoDAF-style fit-for-purpose view from the same canonical basis.
  Unknown viewpoints fail closed."
  [{:eaf/keys [basis incidences]} viewpoint]
  (let [kinds (get viewpoints viewpoint)]
    (when-not kinds
      (throw (ex-info "unknown EAF viewpoint"
                      {:eaf.problem/code :viewpoint/unknown
                       :eaf/viewpoint viewpoint})))
    {:eaf/viewpoint viewpoint
     :eaf/basis basis
     :eaf/incidences
     (into (sorted-map)
           (filter (fn [[_ incidence]]
                     (contains? kinds (:incidence/kind incidence))))
           incidences)}))
