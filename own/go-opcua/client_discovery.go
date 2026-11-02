// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"strings"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

func (g *globals) endpoints(ctx context.Context) outcome {
	opts, err := g.connectionOptions(ctx)
	if err != nil {
		return failure(exitInternal, "internal", err.Error(), ua.StatusBadInternalError)
	}
	eps, err := opcua.GetEndpoints(ctx, g.dialURL(), opts...)
	if err != nil {
		return g.classifyWait(err)
	}
	results := make([]any, len(eps))
	for i, ep := range eps {
		results[i] = map[string]any{"url": ep.EndpointURL, "securityPolicy": ep.SecurityPolicyURI, "securityMode": modeName(ep.SecurityMode)}
	}
	return outcome{status: ua.StatusOK, results: results}
}

func modeName(m ua.MessageSecurityMode) string {
	return strings.TrimPrefix(m.String(), "MessageSecurityMode")
}

func (g *globals) findServers(ctx context.Context) outcome {
	opts, err := g.connectionOptions(ctx)
	if err != nil {
		return failure(exitInternal, "internal", err.Error(), ua.StatusBadInternalError)
	}
	apps, err := opcua.FindServers(ctx, g.dialURL(), opts...)
	if err != nil {
		return g.classifyWait(err)
	}
	results := make([]any, len(apps))
	for i, app := range apps {
		urls := app.DiscoveryURLs
		if urls == nil {
			urls = []string{}
		}
		results[i] = map[string]any{"applicationUri": app.ApplicationURI, "applicationName": localizedText(app.ApplicationName), "productUri": app.ProductURI, "discoveryUrls": urls}
	}
	return outcome{status: ua.StatusOK, results: results}
}
