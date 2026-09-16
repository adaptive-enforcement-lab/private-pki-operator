// Package controller holds the reconcilers that drive the private PKI.
//
// PKIRotationReconciler runs the dual-trust rotation state machine — Idle,
// PreservingOldRoot, DualTrustActive, AwaitingReissuance, VerifyingChain,
// Complete — for both the root and the intermediate tiers, orchestrating
// cert-manager and trust-manager rather than reimplementing any cryptography.
package controller
