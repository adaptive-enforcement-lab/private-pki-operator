package controller

// Fleet-state metrics.
//
// The collectors in metrics.go describe ACTIVITY and STATE MACHINE position —
// which phase a rotation holds, how many transitions have happened, what a
// cascade touched. None of them answer the questions an operator actually opens
// a PKI dashboard with: how much of a hierarchy is there, how many roots and
// intermediates does it hang off, how many leaves depend on those, and how far
// across the cluster does it reach.
//
// These are computed at SCRAPE time from the informer cache rather than being
// gauges written by a reconcile loop. A reconcile only ever sees ONE object, so
// keeping a fleet total accurate from per-object events means tracking adds and
// deletes by hand — which drifts the moment an event is missed. The cache is
// already populated and reading it costs no API traffic.

import (
	"context"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// Certificate tiers (label values for descCertificates).
const (
	certTierRoot         = "root"
	certTierIntermediate = "intermediate"
	certTierLeaf         = "leaf"
)

var (
	// descCertificates counts cert-manager Certificates by their position in the
	// hierarchy. Tier is derived from what the PKIRotation CRs declare rather than
	// guessed from the certificate: a root is a cert some rotation names as its
	// spec.rootCA, an intermediate is any other CA cert, and everything else is a
	// leaf. That keeps the count aligned with what the operator actually manages
	// instead of with every Certificate that happens to exist.
	descCertificates = prometheus.NewDesc(
		metricPrefix+"certificates",
		"cert-manager Certificates in the PKI hierarchy, by tier (root, intermediate, leaf).", []string{"tier"}, nil,
	)

	// descCertificatesReady counts the subset of the above that are Ready. Read
	// against descCertificates it is the health of the whole hierarchy in one
	// ratio — the number an incident starts from.
	descCertificatesReady = prometheus.NewDesc(
		metricPrefix+"certificates_ready",
		"cert-manager Certificates in the PKI hierarchy whose Ready condition is True, by tier.",
		[]string{"tier"}, nil,
	)

	// descNamespaces is how far the hierarchy reaches. A rotation cascade touches
	// every one of these, so it is the blast radius of a root CA rollover.
	descNamespaces = prometheus.NewDesc(
		metricPrefix+"namespaces", "Distinct namespaces containing at least one Certificate in the PKI hierarchy.",
		nil, nil,
	)

	// descRotations counts the PKIRotation CRs themselves, by role. This is the
	// denominator for every phase panel: "4 of 6 Idle" needs the 6.
	descRotations = prometheus.NewDesc(
		metricPrefix+"rotations", "PKIRotation objects under management, by role.", []string{"role"}, nil,
	)
)

// FleetCollector reports PKI hierarchy counts at scrape time.
//
// NOTE ON REPLICAS: the cache runs on every replica, not only the elected
// leader, so with replicas > 1 each pod reports the same figures under its own
// pod label. Aggregate these series with MAX, not SUM.
type FleetCollector struct {
	Reader client.Reader
}

// NewFleetCollector returns a collector reading from the manager's cache.
func NewFleetCollector(r client.Reader) *FleetCollector { return &FleetCollector{Reader: r} }

// Describe implements prometheus.Collector.
func (c *FleetCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descCertificates
	ch <- descCertificatesReady
	ch <- descNamespaces
	ch <- descRotations
}

// Collect lists from the cache.
//
// A List error drops the affected series rather than emitting a zero. Zero is a
// meaningful answer here — "this hierarchy has no intermediates" — and emitting
// it for a failed read would report a healthy empty estate when the truth is
// that nothing could be counted. An absent series is the honest signal.
func (c *FleetCollector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()

	var rotations platformv1alpha1.PKIRotationList
	if err := c.Reader.List(ctx, &rotations); err == nil {
		byRole := map[string]int{
			string(platformv1alpha1.RoleRootCA):         0,
			string(platformv1alpha1.RoleIntermediateCA): 0,
		}
		for i := range rotations.Items {
			role := string(rotations.Items[i].Spec.Role)
			if role == "" {
				// spec.role is omitempty and defaults to RootCA; count it as one
				// rather than inventing a third bucket for the default.
				role = string(platformv1alpha1.RoleRootCA)
			}
			byRole[role]++
		}
		for role, n := range byRole {
			ch <- prometheus.MustNewConstMetric(descRotations, prometheus.GaugeValue, float64(n), role)
		}
	}

	var certs cmv1.CertificateList
	if err := c.Reader.List(ctx, &certs); err != nil {
		return
	}

	// Roots are named by the rotations, so the tier split needs both lists. When
	// the rotation list failed above this set is empty, which demotes roots to
	// "intermediate" — so the tier series are only emitted when both reads
	// succeeded.
	roots := rootCertificateRefs(&rotations)

	total := map[string]int{certTierRoot: 0, certTierIntermediate: 0, certTierLeaf: 0}
	ready := map[string]int{certTierRoot: 0, certTierIntermediate: 0, certTierLeaf: 0}
	namespaces := map[string]struct{}{}

	for i := range certs.Items {
		cert := &certs.Items[i]
		tier := certTierLeaf
		switch {
		case roots[certRef{name: cert.Name, namespace: cert.Namespace}]:
			tier = certTierRoot
		case cert.Spec.IsCA:
			tier = certTierIntermediate
		}
		total[tier]++
		if isCertificateResourceReady(cert) {
			ready[tier]++
		}
		namespaces[cert.Namespace] = struct{}{}
	}

	for _, tier := range []string{certTierRoot, certTierIntermediate, certTierLeaf} {
		ch <- prometheus.MustNewConstMetric(descCertificates, prometheus.GaugeValue, float64(total[tier]), tier)
		ch <- prometheus.MustNewConstMetric(descCertificatesReady, prometheus.GaugeValue, float64(ready[tier]), tier)
	}
	ch <- prometheus.MustNewConstMetric(descNamespaces, prometheus.GaugeValue, float64(len(namespaces)))
}

// certRef identifies a Certificate by namespace and name.
type certRef struct {
	name      string
	namespace string
}

// rootCertificateRefs returns every Certificate a PKIRotation declares as its
// root CA. A cert can be named by more than one rotation; the set collapses that.
func rootCertificateRefs(rotations *platformv1alpha1.PKIRotationList) map[certRef]bool {
	roots := map[certRef]bool{}
	if rotations == nil {
		return roots
	}
	for i := range rotations.Items {
		ref := rotations.Items[i].Spec.RootCA
		if ref.CertificateName == "" {
			continue
		}
		roots[certRef{name: ref.CertificateName, namespace: ref.CertificateNamespace}] = true
	}
	return roots
}
