// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/ua"
)

// userCredentialCertificateType is the default type of the DefaultUserTokenGroup (§1).
const userCredentialCertificateType = 15181

// pushBudget is the time of all the steps of `push` on one session. CreateSelfSigned
// generates a key on the server.
const pushBudget = 60 * time.Second

// pushGroup is a certificate group of §1 "push flags".
type pushGroup struct {
	id, trustList *ua.NodeID
	defaultType   *ua.NodeID
}

var pushGroups = map[string]pushGroup{
	"Application": {gds.DefaultApplicationGroup, gds.DefaultTrustList, gds.RsaSha256ApplicationCertificateType},
	"Https":       {gds.DefaultHTTPSGroup, gds.HTTPSTrustList, gds.HTTPSCertificateType},
	"UserToken":   {gds.DefaultUserTokenGroup, gds.UserTokenTrustList, ua.NewNumericNodeID(0, userCredentialCertificateType)},
}

// pushFlags are the flags of `push` (§1).
type pushFlags struct {
	group, typeID, addFile, remove, deleteType, updateFile, updateKey, keyFormat, subject string
	issuer, getCerts, selfSigned, csr, reset, apply, cancel, diagnostics                  bool
	dns, ip, issuerFiles                                                                  repeated
	lifetimeDays, keySize                                                                 uint

	groupRef          pushGroup
	certType, deleted *ua.NodeID
	add, update, key  []byte
	issuers           [][]byte
}

func (f *pushFlags) define(fs *flag.FlagSet) {
	fs.StringVar(&f.group, "group", "Application", "Application, Https or UserToken")
	fs.StringVar(&f.typeID, "certificate-type-id", "", "certificate type")
	fs.StringVar(&f.addFile, "add-certificate", "", "AddCertificate")
	fs.StringVar(&f.remove, "remove-certificate", "", "RemoveCertificate, a thumbprint")
	fs.BoolVar(&f.issuer, "issuer", false, "the issuer list")
	fs.BoolVar(&f.getCerts, "get-certificates", false, "GetCertificates")
	fs.BoolVar(&f.selfSigned, "create-self-signed", false, "CreateSelfSignedCertificate")
	fs.StringVar(&f.subject, "subject", "", "subject of the self-signed certificate")
	fs.Var(&f.dns, "dns", "DNS name, repeatable")
	fs.Var(&f.ip, "ip", "IP address, repeatable")
	fs.UintVar(&f.lifetimeDays, "lifetime-days", 365, "lifetime of the self-signed certificate")
	fs.UintVar(&f.keySize, "key-size", 0, "key size of the self-signed certificate")
	fs.StringVar(&f.deleteType, "delete-certificate", "", "DeleteCertificate of this type")
	fs.StringVar(&f.updateFile, "update-certificate", "", "UpdateCertificate")
	fs.StringVar(&f.updateKey, "update-private-key", "", "private key of the update")
	fs.StringVar(&f.keyFormat, "private-key-format", "", "PEM or PFX")
	fs.Var(&f.issuerFiles, "issuer-certificate", "issuer of the update, repeatable")
	fs.BoolVar(&f.csr, "csr", false, "CreateSigningRequest")
	fs.BoolVar(&f.reset, "reset-to-defaults", false, "ResetToServerDefaults")
	fs.BoolVar(&f.apply, "apply", false, "ApplyChanges")
	fs.BoolVar(&f.cancel, "cancel", false, "CancelChanges")
	fs.BoolVar(&f.diagnostics, "transaction-diagnostics", false, "read the TransactionDiagnostics")
}

// validate is everything that is an input error before connecting (§1).
func (f *pushFlags) validate() error {
	group, ok := pushGroups[f.group]
	if !ok {
		return errors.New("--group: " + f.group)
	}
	f.groupRef, f.certType = group, group.defaultType
	var err error
	if f.typeID != "" {
		if f.certType, err = ua.ParseNodeID(f.typeID); err != nil {
			return errors.New("--certificate-type-id: " + f.typeID)
		}
	}
	if f.deleteType != "" {
		if f.deleted, err = ua.ParseNodeID(f.deleteType); err != nil {
			return errors.New("--delete-certificate: " + f.deleteType)
		}
	}
	if f.lifetimeDays > 65535 || f.keySize > 65535 {
		return errors.New("--lifetime-days and --key-size are UInt16")
	}
	if f.apply && f.cancel {
		return errors.New("--apply and --cancel exclude each other")
	}
	if f.addFile != "" {
		if f.add, err = readDER(f.addFile); err != nil {
			return err
		}
	}
	if f.updateFile != "" {
		if f.update, err = readDER(f.updateFile); err != nil {
			return err
		}
	}
	for _, file := range f.issuerFiles {
		der, err := readDER(file)
		if err != nil {
			return err
		}
		f.issuers = append(f.issuers, der)
	}
	if f.updateKey != "" {
		if f.key, err = os.ReadFile(f.updateKey); err != nil {
			return err
		}
		if f.keyFormat == "" {
			f.keyFormat = "PEM"
			switch strings.ToLower(filepath.Ext(f.updateKey)) {
			case ".pfx", ".p12":
				f.keyFormat = "PFX"
			}
		}
	} else if f.keyFormat != "" {
		return errors.New("--private-key-format needs --update-private-key")
	}
	if f.keyFormat != "" && f.keyFormat != "PEM" && f.keyFormat != "PFX" {
		return errors.New("--private-key-format: " + f.keyFormat)
	}
	// §1: what they create or delete is not installed without --apply.
	if (f.selfSigned || f.deleted != nil) && !f.apply {
		f.cancel = true
	}
	return nil
}

func pushCommand(fs *flag.FlagSet) command {
	f := &pushFlags{}
	f.define(fs)
	return command{validate: f.validate, run: f.run, budget: func() time.Duration { return pushBudget }}
}

// base64s are DER items in the form of §4.
func base64s(items [][]byte) []string {
	out := make([]string, len(items))
	for i, b := range items {
		out[i] = base64.StdEncoding.EncodeToString(b)
	}
	return out
}

func nodeIDStrings(ids []*ua.NodeID) []string {
	out := make([]string, len(ids))
	for i, n := range ids {
		out[i] = nodeIDString(n)
	}
	return out
}

// trustListJSON is a TrustListDataType in §4 `push`.
func trustListJSON(tl *ua.TrustListDataType) map[string]any {
	return map[string]any{
		"specifiedLists":      tl.SpecifiedLists,
		"trustedCertificates": base64s(tl.TrustedCertificates),
		"trustedCrls":         base64s(tl.TrustedCrls),
		"issuerCertificates":  base64s(tl.IssuerCertificates),
		"issuerCrls":          base64s(tl.IssuerCrls),
	}
}

// statusFrom is the status of a failed step: that of the server, or one that says
// the answer could not be used.
func statusFrom(err error) ua.StatusCode {
	var status ua.StatusCode
	if errors.As(err, &status) {
		return status
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ua.StatusBadTimeout
	}
	return ua.StatusBadUnexpectedError
}

// stepResult collects the keys of the steps of a multi-step command: the steps run
// on one session and stop at the first Bad status (§1).
type stepResult struct {
	out map[string]any
	res *outcome
}

// step records the status of a step under key and says whether the command goes on.
func (r *stepResult) step(key string, err error) bool {
	status := ua.StatusOK
	if err != nil {
		status = statusFrom(err)
	}
	if key != "" {
		r.out[key] = statusOf(status)
	}
	if err == nil {
		return true
	}
	r.fail(fmt.Errorf("%s: %w", strings.TrimSuffix(key, "Status"), err), status)
	return false
}

func (r *stepResult) fail(err error, status ua.StatusCode) {
	res := failure(exitService, "service", err.Error(), status)
	r.res = &res
}

func (r *stepResult) outcome() outcome {
	if r.res != nil {
		r.res.results = []any{r.out}
		return *r.res
	}
	return outcome{status: ua.StatusOK, results: []any{r.out}}
}

// diagnosticsJSON is the transactionDiagnostics of §4.
func diagnosticsJSON(d *gds.TransactionDiagnostics) map[string]any {
	errs := make([]any, len(d.Errors))
	for i, e := range d.Errors {
		var message any
		if e.Message != nil {
			message = e.Message.Text
		}
		errs[i] = map[string]any{"targetId": nodeIDString(e.TargetID), "error": statusOf(e.Error), "message": message}
	}
	out := map[string]any{
		"startTime": nil, "endTime": nil, "result": statusOf(d.Result),
		"affectedTrustLists": nodeIDStrings(d.AffectedTrustLists), "affectedCertificateGroups": nodeIDStrings(d.AffectedCertificateGroups),
		"errors": errs,
	}
	if !d.StartTime.IsZero() {
		out["startTime"] = timeString(d.StartTime)
	}
	if !d.EndTime.IsZero() {
		out["endTime"] = timeString(d.EndTime)
	}
	return out
}

// run is the order of §1 "push flags".
func (f *pushFlags) run(ctx context.Context, c *opcua.Client) outcome {
	g := gds.New(c).WithTrustList(f.groupRef.trustList)
	r := &stepResult{out: map[string]any{"certificateGroupId": nodeIDString(f.groupRef.id)}}
	tl, err := g.ReadTrustList(ctx, ua.TrustListMasksAll)
	if err != nil {
		r.fail(fmt.Errorf("the trust list of %s: %w", f.group, err), statusFrom(err))
		return r.outcome()
	}
	r.out["trustList"] = trustListJSON(tl)
	if !f.changes(ctx, g, r) {
		return r.outcome()
	}
	applied, ok := false, true
	if f.apply {
		applied, ok = true, r.step("applyChangesStatus", g.ApplyChanges(ctx))
	}
	if ok && f.cancel {
		ok = r.step("cancelChangesStatus", g.CancelChanges(ctx))
	}
	// The diagnostics explain a failed ApplyChanges too (§4).
	if f.diagnostics && (ok || applied) {
		d, err := g.TransactionDiagnostics(ctx)
		r.out["transactionDiagnosticsStatus"] = statusOf(ua.StatusOK)
		if err != nil {
			r.out["transactionDiagnosticsStatus"] = statusOf(statusFrom(err))
			if ok {
				r.fail(fmt.Errorf("transactionDiagnostics: %w", err), statusFrom(err))
				ok = false
			}
		} else {
			r.out["transactionDiagnostics"] = diagnosticsJSON(d)
		}
	}
	if ok {
		after, err := g.ReadTrustList(ctx, ua.TrustListMasksAll)
		if err != nil {
			r.fail(fmt.Errorf("the trust list again: %w", err), statusFrom(err))
			return r.outcome()
		}
		r.out["trustListAfter"] = trustListJSON(after)
	}
	return r.outcome()
}

// changes are the steps from AddCertificate to ResetToServerDefaults.
func (f *pushFlags) changes(ctx context.Context, g *gds.Client, r *stepResult) bool {
	trusted := !f.issuer
	if f.add != nil && !r.step("addCertificateStatus", g.AddCertificate(ctx, f.add, trusted)) {
		return false
	}
	if f.remove != "" && !r.step("removeCertificateStatus", g.RemoveCertificate(ctx, f.remove, trusted)) {
		return false
	}
	if f.getCerts {
		types, certs, err := g.GetCertificates(ctx, f.groupRef.id)
		if !r.step("getCertificatesStatus", err) {
			return false
		}
		r.out["certificateTypeIds"], r.out["certificates"] = nodeIDStrings(types), base64s(certs)
	}
	if f.selfSigned {
		cert, err := g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{
			CertificateGroup: f.groupRef.id, CertificateType: f.certType, SubjectName: f.subject,
			DNSNames: f.dns, IPAddresses: f.ip, LifetimeInDays: uint16(f.lifetimeDays), KeySizeInBits: uint16(f.keySize), // #nosec G115 -- validated
		})
		if !r.step("createSelfSignedCertificateStatus", err) {
			return false
		}
		r.out["selfSignedCertificate"] = base64.StdEncoding.EncodeToString(cert)
	}
	if f.deleted != nil && !r.step("deleteCertificateStatus", g.DeleteCertificate(ctx, f.groupRef.id, f.deleted)) {
		return false
	}
	if f.update != nil {
		required, err := g.UpdateCertificate(ctx, &gds.CertificateUpdate{
			CertificateGroup: f.groupRef.id, CertificateType: f.certType, Certificate: f.update,
			IssuerCertificates: f.issuers, PrivateKeyFormat: f.keyFormat, PrivateKey: f.key,
		})
		if !r.step("updateCertificateStatus", err) {
			return false
		}
		r.out["applyChangesRequired"] = required
	}
	if f.csr {
		csr, err := g.CreateSigningRequest(ctx, &gds.SigningRequest{CertificateGroup: f.groupRef.id, CertificateType: f.certType})
		if !r.step("createSigningRequestStatus", err) {
			return false
		}
		r.out["certificateSigningRequest"] = base64.StdEncoding.EncodeToString(csr)
	}
	rejected, err := g.GetRejectedList(ctx)
	if !r.step("getRejectedListStatus", err) {
		return false
	}
	r.out["rejectedCertificates"] = base64s(rejected)
	return !f.reset || r.step("resetToServerDefaultsStatus", g.ResetToServerDefaults(ctx))
}
