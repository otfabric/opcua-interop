// SPDX-License-Identifier: MIT

package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsserver"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// wellKnownRoles are the roles of Part 3 §4.9.2 a fixture user may have by BrowseName
// (§15). AuthenticatedUser goes with every user.
var wellKnownRoles = map[string]ua.WellKnownRole{
	"Observer": ua.RoleObserver, "Operator": ua.RoleOperator, "Engineer": ua.RoleEngineer,
	"Supervisor": ua.RoleSupervisor, "ConfigureAdmin": ua.RoleConfigureAdmin, "SecurityAdmin": ua.RoleSecurityAdmin,
}

// hasGDSRole says that a fixture user administers a GDS, which is what makes this
// server one (§16.1).
func (fx *fixture) hasGDSRole() bool {
	for _, u := range fx.Users {
		if slices.Contains(u.Roles, "DiscoveryAdmin") || slices.Contains(u.Roles, "CertificateAuthorityAdmin") {
			return true
		}
	}
	return false
}

// roleMapper gives a fixture user the roles of its `roles`. The roles of a GDS only
// exist once it is attached, after the server options are read.
func roleMapper(fx *fixture, directory func() *gdsserver.GDS) server.RoleMapper {
	return func(token ua.IdentityToken) []*ua.NodeID {
		user, ok := token.(*ua.UserNameIdentityToken)
		if !ok {
			return server.DefaultRoleMapper(token)
		}
		roles := []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID()}
		for _, u := range fx.Users {
			if u.Username != user.UserName {
				continue
			}
			for _, name := range u.Roles {
				if role, ok := wellKnownRoles[name]; ok {
					roles = append(roles, role.NodeID())
				}
				if g := directory(); g != nil && name == "DiscoveryAdmin" {
					roles = append(roles, g.DiscoveryAdminRole())
				}
				if g := directory(); g != nil && name == "CertificateAuthorityAdmin" {
					roles = append(roles, g.CertificateAuthorityAdminRole())
				}
			}
		}
		return roles
	}
}

// attachGDS makes the server the Global Discovery Server of §16.1: every request is
// approved at once, and nothing outlives the container.
func attachGDS(s *server.Server) (*gdsserver.GDS, error) {
	return gdsserver.Attach(s, gdsserver.Config{
		AutoApprove: true,
		CAName:      "opcua-interop otfabric CA",
		CertificateTypes: []*ua.NodeID{
			gds.RsaSha256ApplicationCertificateType, gds.EccNistP256ApplicationCertificateType,
		},
	})
}

// pushManagement is the ServerConfiguration of §15. Its application trust list is the
// one new channels are validated with: <pki-dir>/trusted/certs. The other groups start
// with the same store, for the X.509 user tokens and the TLS clients.
func pushManagement(trusted [][]byte) server.PushManagement {
	list := func() *ua.TrustListDataType { return &ua.TrustListDataType{TrustedCertificates: trusted} }
	return server.PushManagement{TrustList: list(), UserTokenTrustList: list(), HTTPSTrustList: list()}
}

// trustedCertificates are the DER certificates of <pki-dir>/trusted/certs.
func trustedCertificates(pkiDir string) ([][]byte, error) {
	files, err := filepath.Glob(filepath.Join(pkiDir, "trusted", "certs", "*"))
	if err != nil {
		return nil, err
	}
	var trusted [][]byte
	for _, file := range files {
		if info, err := os.Stat(file); err != nil || info.IsDir() {
			continue
		}
		der, err := readDER(file)
		if err != nil {
			return nil, err
		}
		if _, err := x509.ParseCertificate(der); err != nil {
			continue
		}
		trusted = append(trusted, der)
	}
	return trusted, nil
}
