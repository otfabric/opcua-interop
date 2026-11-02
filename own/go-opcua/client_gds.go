// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/ua"
)

// gdsBudget is the time of the steps of `gds-pull` besides polling FinishRequest.
const gdsBudget = 60 * time.Second

// gdsFlags are the flags of `gds-pull` (§16.2).
type gdsFlags struct {
	appURI, appType, request, certType string
	discovery                          repeated
	revoke, unregister                 bool
	finishTimeoutMS                    int64
}

func gdsCommand(fs *flag.FlagSet) command {
	f := &gdsFlags{}
	fs.StringVar(&f.appURI, "app-uri", "urn:opcua-interop:gds-pull:app", "ApplicationUri of the record")
	fs.StringVar(&f.appType, "app-type", "Server", "Server, Client or ClientAndServer")
	fs.Var(&f.discovery, "discovery-url", "DiscoveryUrl of the record, repeatable")
	fs.StringVar(&f.request, "request", "csr", "csr or new-key-pair")
	fs.StringVar(&f.certType, "certificate-type", "RsaSha256", "RsaSha256 or NistP256")
	fs.BoolVar(&f.revoke, "revoke", false, "RevokeCertificate, then CheckRevocationStatus")
	fs.BoolVar(&f.unregister, "unregister", false, "UnregisterApplication at the end")
	fs.Int64Var(&f.finishTimeoutMS, "finish-timeout-ms", 30000, "how long FinishRequest is polled")
	return command{validate: f.validate, run: f.run, budget: func() time.Duration {
		return gdsBudget + time.Duration(f.finishTimeoutMS)*time.Millisecond
	}}
}

func (f *gdsFlags) validate() error {
	switch f.appType {
	case "Server", "Client", "ClientAndServer":
	default:
		return errors.New("--app-type: " + f.appType)
	}
	if f.request != "csr" && f.request != "new-key-pair" {
		return errors.New("--request: " + f.request)
	}
	if f.certType != "RsaSha256" && f.certType != "NistP256" {
		return errors.New("--certificate-type: " + f.certType)
	}
	if f.finishTimeoutMS <= 0 {
		return errors.New("--finish-timeout-ms must be positive")
	}
	if len(f.discovery) == 0 {
		f.discovery = repeated{"opc.tcp://localhost:4850"}
	}
	return nil
}

// appName is the last segment of the URI (§16.2).
func (f *gdsFlags) appName() string {
	i := strings.LastIndexAny(f.appURI, ":/")
	if name := f.appURI[i+1:]; name != "" {
		return name
	}
	return "opcua-interop gds-pull app"
}

// record is the ApplicationRecordDataType of step 2.
func (f *gdsFlags) record() *gds.ApplicationRecord {
	r := &gds.ApplicationRecord{
		ApplicationURI: f.appURI, ApplicationType: ua.ApplicationTypeServer,
		ApplicationNames: []*ua.LocalizedText{ua.NewLocalizedTextWithLocale(f.appName(), "en-US")},
		ProductURI:       "urn:opcua-interop:" + adapterName,
	}
	switch f.appType {
	case "Client":
		r.ApplicationType = ua.ApplicationTypeClient
	case "ClientAndServer":
		r.ApplicationType = ua.ApplicationTypeClientAndServer
	}
	if f.appType != "Client" {
		r.DiscoveryURLs, r.ServerCapabilities = f.discovery, []string{"NA"}
	}
	return r
}

func (f *gdsFlags) certificateType() *ua.NodeID {
	if f.certType == "NistP256" {
		return gds.EccNistP256ApplicationCertificateType
	}
	return gds.RsaSha256ApplicationCertificateType
}

// signingRequest is the PKCS #10 request with a fresh key (§16.2 step 3).
func (f *gdsFlags) signingRequest() ([]byte, error) {
	var key crypto.Signer
	var err error
	if f.certType == "NistP256" {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, err
	}
	return gds.NewCertificateRequest(key, f.appURI, "CN="+f.appName(), []string{"localhost"})
}

// start is step 3.
func (f *gdsFlags) start(ctx context.Context, p *gds.PullClient, app, group *ua.NodeID) (*ua.NodeID, error) {
	if f.request == "new-key-pair" {
		return p.StartNewKeyPairRequest(ctx, app, &gds.NewKeyPairRequest{
			CertificateGroup: group, CertificateType: f.certificateType(), SubjectName: "CN=" + f.appName(),
			DomainNames: []string{"localhost"}, PrivateKeyFormat: gds.PrivateKeyFormatPEM,
		})
	}
	csr, err := f.signingRequest()
	if err != nil {
		return nil, err
	}
	return p.StartSigningRequest(ctx, app, group, f.certificateType(), csr)
}

// finish is step 4: FinishRequest while it answers BadNothingToDo. Its own clock,
// since the budget of the whole command is shorter than the one this flag gives.
func (f *gdsFlags) finish(ctx context.Context, p *gds.PullClient, app, request *ua.NodeID) (*gds.IssuedCertificate, error) {
	deadline := time.Now().Add(time.Duration(f.finishTimeoutMS) * time.Millisecond)
	for {
		issued, err := p.FinishRequest(ctx, app, request)
		if !errors.Is(err, ua.StatusBadNothingToDo) || time.Now().After(deadline) {
			return issued, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// run is the order of §16.2, stopping at the first Bad status.
func (f *gdsFlags) run(ctx context.Context, c *opcua.Client) outcome {
	p := gds.NewPullClient(c)
	r := &stepResult{out: map[string]any{}}
	records, err := p.FindApplications(ctx, f.appURI)
	if err != nil {
		r.out["findApplicationsStatus"] = statusOf(statusFrom(err))
		r.fail(fmt.Errorf("findApplications: %w", err), statusFrom(err))
		return r.outcome()
	}
	ids := make([]string, len(records))
	for i, rec := range records {
		ids[i] = nodeIDString(rec.ApplicationID)
	}
	r.out["findApplications"] = ids
	var app *ua.NodeID
	if len(records) > 0 {
		app = records[0].ApplicationID
		r.out["registered"] = false
	} else {
		app, err = p.RegisterApplication(ctx, f.record())
		if !r.step("registerStatus", err) {
			return r.outcome()
		}
		r.out["registered"] = true
	}
	r.out["applicationId"] = nodeIDString(app)
	if issued := f.issue(ctx, p, app, r); issued != nil {
		f.check(ctx, p, app, issued, r)
	}
	return r.outcome()
}

// issue is steps 3 and 4.
func (f *gdsFlags) issue(ctx context.Context, p *gds.PullClient, app *ua.NodeID, r *stepResult) *gds.IssuedCertificate {
	group, err := p.DefaultApplicationGroup(ctx)
	if !r.step("startRequestStatus", err) {
		return nil
	}
	r.out["requestKind"] = f.request
	request, err := f.start(ctx, p, app, group)
	if !r.step("startRequestStatus", err) {
		return nil
	}
	r.out["requestId"] = nodeIDString(request)
	issued, err := f.finish(ctx, p, app, request)
	if !r.step("finishRequestStatus", err) {
		return nil
	}
	r.out["certificate"] = base64.StdEncoding.EncodeToString(issued.Certificate)
	if f.request == "new-key-pair" {
		r.out["privateKeyFormat"] = gds.PrivateKeyFormatPEM
		r.out["privateKey"] = base64.StdEncoding.EncodeToString(issued.PrivateKey)
	}
	r.out["issuerCertificates"] = base64s(issued.IssuerCertificates)
	return issued
}

// check is steps 5 to 9.
func (f *gdsFlags) check(ctx context.Context, p *gds.PullClient, app *ua.NodeID, issued *gds.IssuedCertificate, r *stepResult) {
	group, err := p.DefaultApplicationGroup(ctx)
	if err != nil {
		r.fail(err, statusFrom(err))
		return
	}
	groups, err := p.GetCertificateGroups(ctx, app)
	if err != nil {
		r.out["getCertificateGroupsStatus"] = statusOf(statusFrom(err))
		r.fail(fmt.Errorf("getCertificateGroups: %w", err), statusFrom(err))
		return
	}
	r.out["certificateGroups"] = nodeIDStrings(groups)
	list, err := p.GetTrustList(ctx, app, group)
	if err != nil {
		r.out["getTrustListStatus"] = statusOf(statusFrom(err))
		r.fail(fmt.Errorf("getTrustList: %w", err), statusFrom(err))
		return
	}
	r.out["trustListId"] = nodeIDString(list)
	tl, err := p.ReadTrustList(ctx, app, group)
	if err != nil {
		r.out["readTrustListStatus"] = statusOf(statusFrom(err))
		r.fail(fmt.Errorf("readTrustList: %w", err), statusFrom(err))
		return
	}
	r.out["trustList"] = trustListJSON(tl)
	required, err := p.GetCertificateStatus(ctx, app, group, f.certificateType())
	if !r.step("getCertificateStatusStatus", err) {
		return
	}
	r.out["updateRequired"] = required
	if f.revoke {
		if !r.step("revokeStatus", p.RevokeCertificate(ctx, app, issued.Certificate)) {
			return
		}
		status, _, err := p.CheckRevocationStatus(ctx, issued.Certificate)
		if !r.step("checkRevocationStatus", err) {
			return
		}
		r.out["certificateStatus"] = statusOf(status)
	}
	if f.unregister {
		r.step("unregisterStatus", p.UnregisterApplication(ctx, app))
	}
}
