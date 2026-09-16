package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// errStatusWriteFailed simulates a status subresource write that will not land —
// a conflict loop, a revoked RBAC grant, an unreachable API server.
var errStatusWriteFailed = errors.New("simulated status write failure")

// recordingSink captures what was logged, so the test can assert the failure was
// actually reported rather than merely not returned.
type recordingSink struct {
	errs []string
}

func (s *recordingSink) Init(logr.RuntimeInfo)               {}
func (s *recordingSink) Enabled(int) bool                    { return true }
func (s *recordingSink) Info(int, string, ...any)            {}
func (s *recordingSink) WithValues(...any) logr.LogSink      { return s }
func (s *recordingSink) WithName(string) logr.LogSink        { return s }
func (s *recordingSink) Error(_ error, msg string, _ ...any) { s.errs = append(s.errs, msg) }

// A failed condition write must be LOGGED, not discarded. Before this, the error
// was assigned to _ at eight call sites: a write that kept failing left the CR
// with no condition and nothing anywhere saying why — the same shape as #259,
// where a phase that was never written went unnoticed for four weeks.
func TestUpdateConditionStatus_LogsAFailedWrite(t *testing.T) {
	sink := &recordingSink{}
	ctx := logf.IntoContext(context.Background(), logr.New(sink))

	pkir := rootPKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseVerifyingChain

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(pkir).
		WithStatusSubresource(pkir).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(context.Context, client.Client, string, client.Object,
				...client.SubResourceUpdateOption,
			) error {
				return errStatusWriteFailed
			},
		}).Build()
	r := &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(10)}

	r.updateConditionStatus(ctx, pkir, "chain not yet verified")

	if len(sink.errs) != 1 {
		t.Fatalf("logged %d errors, want exactly 1 — a failed condition write must be reported", len(sink.errs))
	}
}

// The helper must not abort the caller. Every call site has already decided what
// happens next — return an error, or requeue — and a failed diagnostic write
// should change neither. It returns nothing precisely so it cannot.
func TestUpdateConditionStatus_DoesNotDisturbASuccessfulWrite(t *testing.T) {
	sink := &recordingSink{}
	ctx := logf.IntoContext(context.Background(), logr.New(sink))

	pkir := rootPKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseVerifyingChain

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(10)}

	r.setCondition(
		pkir, platformv1alpha1.ConditionChainVerified, metav1.ConditionFalse, "LeafReissuancePending",
		"pending: [a/b]",
	)
	r.updateConditionStatus(ctx, pkir, "chain not yet verified")

	if len(sink.errs) != 0 {
		t.Errorf("logged %d errors on a successful write, want 0: %v", len(sink.errs), sink.errs)
	}

	var stored platformv1alpha1.PKIRotation
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pkir), &stored); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if len(stored.Status.Conditions) != 1 {
		t.Errorf(
			"persisted %d conditions, want 1 — the write must still actually happen", len(stored.Status.Conditions),
		)
	}
}
