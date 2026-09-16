package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// Metric name prefix. The operator had no collectors at all before this — the
// endpoint was disabled and nothing was registered — so "pkirotation_" is the
// canonical prefix for this project; keep every new collector under it.
const metricPrefix = "pkirotation_"

// Metric label names.
const (
	// metricLabelName is the PKIRotation object name.
	//
	// Labelling by object name is normally forbidden — it is how a metric's
	// cardinality becomes unbounded. It is sound HERE and only here because the
	// PKIRotation population is bounded by the number of CA certificates in the
	// PKI hierarchy: 5-6 per cluster today, tens at the very worst. The label is
	// also the only thing that answers the question this operator exists to
	// answer — "WHICH rotation is stuck" — which a per-outcome aggregate cannot.
	//
	// It is deliberately NOT applied to the counters below: those partition on
	// closed sets, where the aggregate is the useful view and the object detail
	// belongs in Events and logs.
	metricLabelName = "name"

	// metricLabelRole is RootCA or IntermediateCA — a closed set of two.
	metricLabelRole = "role"

	// metricLabelPhase is the state machine phase; closed set, see allPhases.
	metricLabelPhase = "phase"

	// metricLabelFrom and metricLabelTo bound a phase transition.
	metricLabelFrom = "from"
	metricLabelTo   = "to"

	// metricLabelKind distinguishes a downstream CA cert from a leaf cert.
	metricLabelKind = "kind"
)

// Downstream certificate kinds (label values for pkiRotationDownstreamReissuedTotal).
const (
	downstreamKindCA   = "ca"
	downstreamKindLeaf = "leaf"
)

// phaseUnset is the label value used when a PKIRotation carries no phase at all.
//
// An empty status.phase is a real, observed state — see issue #259, where two
// CRs sat with a populated SKID and no phase across three environments for
// weeks. Exporting it as "" would make the series indistinguishable from a
// missing one; naming it makes "stuck with no phase" directly alertable.
const phaseUnset = "Unset"

// allPhases is every phase the gauge partitions on, including phaseUnset. It is
// the single source of truth for that set: the one-hot gauge must clear every
// OTHER phase on each transition, and a phase missing from this list would keep
// a stale 1 forever after the CR left it.
var allPhases = []string{
	phaseUnset,
	string(platformv1alpha1.PhaseIdle),
	string(platformv1alpha1.PhasePreservingOldRoot),
	string(platformv1alpha1.PhaseDualTrustActive),
	string(platformv1alpha1.PhaseAwaitingReissuance),
	string(platformv1alpha1.PhaseVerifyingChain),
	string(platformv1alpha1.PhaseComplete),
}

var (
	// pkiRotationPhase is a one-hot gauge: exactly one phase series per (name,
	// role) reads 1, every other reads 0.
	//
	// A gauge rather than a counter because the question is "what is the state
	// NOW", and because gauges survive the scrape-timing trap that makes a
	// counter's first increments invisible: a rotation's interesting work happens
	// in seconds, and a counter whose baseline is set at the monitoring system's
	// first scrape reports those increments as zero forever.
	pkiRotationPhase = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: metricPrefix + "phase",
		Help: "Current phase of a PKIRotation, one-hot: 1 for the active phase, 0 for all others.",
	}, []string{metricLabelName, metricLabelRole, metricLabelPhase})

	// pkiRotationTransitionsTotal counts phase transitions. Recorded in
	// transitionTo, which is the single choke point every phase change passes
	// through, so a transition cannot be recorded in one path and missed in
	// another.
	pkiRotationTransitionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: metricPrefix + "transitions_total",
		Help: "Total PKIRotation phase transitions, partitioned by role and by from/to phase.",
	}, []string{metricLabelRole, metricLabelFrom, metricLabelTo})

	// pkiRotationDownstreamReissuedTotal counts certificates a cascade actually
	// triggered. This is the number that says a rotation did work rather than
	// merely changed phase.
	pkiRotationDownstreamReissuedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: metricPrefix + "downstream_reissued_total",
		Help: "Total downstream certificates whose re-issuance was triggered by a rotation cascade.",
	}, []string{metricLabelRole, metricLabelKind})

	// pkiRotationSKIDDriftTotal counts the SKIDDriftDetected reset path — the CA
	// rotated again mid-cascade, so the state machine restarted. A sustained rate
	// means rotations are racing something and never converging.
	pkiRotationSKIDDriftTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: metricPrefix + "skid_drift_total",
		Help: "Total times a CA SKID changed mid-cascade, resetting the rotation to Idle.",
	}, []string{metricLabelRole})

	// pkiRotationReissuanceTimeoutsTotal counts breaches of spec.reissuanceTimeout
	// — cert-manager did not renew within the window the rotation allowed. This is
	// the signal that a rotation is stalled rather than slow.
	pkiRotationReissuanceTimeoutsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: metricPrefix + "reissuance_timeouts_total",
		Help: "Total rotations that exceeded spec.reissuanceTimeout waiting for cert-manager renewal.",
	}, []string{metricLabelRole})
)

func init() {
	metrics.Registry.MustRegister(
		pkiRotationPhase, pkiRotationTransitionsTotal, pkiRotationDownstreamReissuedTotal, pkiRotationSKIDDriftTotal,
		pkiRotationReissuanceTimeoutsTotal,
	)

	// Pre-initialise the role-partitioned counters to zero so every series exists
	// before the first event. Without this a dashboard panel reads "no data"
	// rather than "0" until the first rotation of that kind ever happens, and the
	// two are not the same answer — one means nothing has gone wrong, the other
	// means nothing is being measured.
	for _, role := range []string{
		string(platformv1alpha1.RoleRootCA),
		string(platformv1alpha1.RoleIntermediateCA),
	} {
		pkiRotationSKIDDriftTotal.WithLabelValues(role)
		pkiRotationReissuanceTimeoutsTotal.WithLabelValues(role)
		for _, kind := range []string{downstreamKindCA, downstreamKindLeaf} {
			pkiRotationDownstreamReissuedTotal.WithLabelValues(role, kind)
		}
	}
}

// recordPhase sets the one-hot phase gauge for a PKIRotation, clearing every
// other phase for the same object.
//
// An empty phase is reported as phaseUnset rather than skipped: a CR with no
// phase is exactly the fault #259 describes, and it has to be visible.
func recordPhase(pkir *platformv1alpha1.PKIRotation) {
	if pkir == nil {
		return
	}
	name := pkir.Name
	role := string(pkir.Spec.Role)
	active := string(pkir.Status.Phase)
	if active == "" {
		active = phaseUnset
	}
	for _, phase := range allPhases {
		value := 0.0
		if phase == active {
			value = 1.0
		}
		pkiRotationPhase.WithLabelValues(name, role, phase).Set(value)
	}
}

// forgetPhase drops every phase series for a deleted PKIRotation. Without it the
// gauge would keep reporting the last phase of an object that no longer exists,
// which reads on a dashboard as a rotation permanently stuck in that phase.
//
// It takes a name rather than the object because the only place it can be called
// — the NotFound branch of Reconcile — no longer has the object, and therefore
// does not know which role its series were labelled with. Both roles are cleared
// for that name instead; deleting a label set that was never created is a no-op.
func forgetPhase(name string) {
	if name == "" {
		return
	}
	for _, role := range []string{
		string(platformv1alpha1.RoleRootCA),
		string(platformv1alpha1.RoleIntermediateCA),
		"", // role is omitempty and defaults to RootCA; series may carry the empty value
	} {
		for _, phase := range allPhases {
			pkiRotationPhase.DeleteLabelValues(name, role, phase)
		}
	}
}

// recordTransition counts one phase change. from is the phase the object held
// before the update, which the caller must capture before overwriting it.
func recordTransition(pkir *platformv1alpha1.PKIRotation, from, to platformv1alpha1.PKIRotationPhase) {
	if pkir == nil {
		return
	}
	fromLabel := string(from)
	if fromLabel == "" {
		fromLabel = phaseUnset
	}
	pkiRotationTransitionsTotal.WithLabelValues(string(pkir.Spec.Role), fromLabel, string(to)).Inc()
}

// recordDownstreamReissued counts the certificates one cascade triggered.
func recordDownstreamReissued(pkir *platformv1alpha1.PKIRotation, caCount, leafCount int) {
	if pkir == nil {
		return
	}
	role := string(pkir.Spec.Role)
	if caCount > 0 {
		pkiRotationDownstreamReissuedTotal.WithLabelValues(role, downstreamKindCA).Add(float64(caCount))
	}
	if leafCount > 0 {
		pkiRotationDownstreamReissuedTotal.WithLabelValues(role, downstreamKindLeaf).Add(float64(leafCount))
	}
}

// recordSKIDDrift counts one mid-cascade SKID change.
func recordSKIDDrift(pkir *platformv1alpha1.PKIRotation) {
	if pkir == nil {
		return
	}
	pkiRotationSKIDDriftTotal.WithLabelValues(string(pkir.Spec.Role)).Inc()
}

// recordReissuanceTimeout counts one breach of spec.reissuanceTimeout.
func recordReissuanceTimeout(pkir *platformv1alpha1.PKIRotation) {
	if pkir == nil {
		return
	}
	pkiRotationReissuanceTimeoutsTotal.WithLabelValues(string(pkir.Spec.Role)).Inc()
}
