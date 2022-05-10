/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"fmt"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type AccessInfo struct {
	UnmappedRoles      []string
	Roles              []string
	Traits             wrappers.Traits
	AllowedResourceIDs []types.ResourceID

	RoleSet RoleSet
}

type accessChecker struct {
	info         *AccessInfo
	localCluster string
	RoleSet
}

func NewAccessChecker(info *AccessInfo, localCluster string) *accessChecker {
	fmt.Printf("NIC creating access checker with info: %+v\n", info)
	return &accessChecker{
		info:         info,
		localCluster: localCluster,
		RoleSet:      info.RoleSet,
	}
}

func (a *accessChecker) checkAllowedResources(r AccessCheckable) error {
	if len(a.info.AllowedResourceIDs) == 0 {
		// certificate does not contain a list of specifically allowed
		// resources, only role-based access control is used
		return nil
	}
	for _, resourceID := range a.info.AllowedResourceIDs {
		if resourceID.ClusterName == a.localCluster &&
			resourceID.Kind == r.GetKind() &&
			resourceID.Name == r.GetName() {
			// allowed to access this resource
			return nil
		}
	}
	return trace.AccessDenied("access to %s:%s is not allowed. allowed resources: %v",
		r.GetKind(), r.GetName(), a.info.AllowedResourceIDs)
}

func (a *accessChecker) CheckAccess(r AccessCheckable, mfa AccessMFAParams, matchers ...RoleMatcher) error {
	if err := a.checkAllowedResources(r); err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(a.RoleSet.checkAccess(r, mfa, matchers...))
}

func (a *accessChecker) GetAllowedResourceIDs() []types.ResourceID {
	return a.info.AllowedResourceIDs
}

func LocalAccessInfoFromCertificate(cert *ssh.Certificate, access RoleGetter) (*AccessInfo, error) {
	traits, err := ExtractTraitsFromCert(cert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	roles, err := ExtractRolesFromCert(cert)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleSet, err := FetchRoles(roles, access, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	allowedResourceIDs, err := ExtractAllowedResourcesFromCert(cert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &AccessInfo{
		UnmappedRoles:      roles,
		Roles:              roles,
		Traits:             traits,
		AllowedResourceIDs: allowedResourceIDs,
		RoleSet:            roleSet,
	}, nil
}

func RemoteAccessInfoFromCertificate(cert *ssh.Certificate, access RoleGetter, roleMap types.RoleMap) (*AccessInfo, error) {
	// Old-style SSH certificates don't have traits in metadata.
	traits, err := ExtractTraitsFromCert(cert)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.AccessDenied("failed to parse certificate traits: %v", err)
	}
	if traits == nil {
		traits = make(map[string][]string)
	}
	// Prior to Teleport 6.2 the only trait passed to the remote cluster
	// was the "logins" trait set to the SSH certificate principals.
	//
	// Keep backwards-compatible behavior and set it in addition to the
	// traits extracted from the certificate.
	traits[teleport.TraitLogins] = cert.ValidPrincipals

	unmappedRoles, err := ExtractRolesFromCert(cert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	roles, err := MapRoles(roleMap, unmappedRoles)
	if err != nil {
		return nil, trace.AccessDenied("failed to map roles for user with remote roles %v: %v", unmappedRoles, err)
	}
	if len(roles) == 0 {
		return nil, trace.AccessDenied("no roles mapped for user with remote roles %v", unmappedRoles)
	}
	log.Debugf("Mapped remote roles %v to local roles %v and traits %v.",
		unmappedRoles, roles, traits)

	roleSet, err := FetchRoles(roles, access, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	allowedResourceIDs, err := ExtractAllowedResourcesFromCert(cert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &AccessInfo{
		UnmappedRoles:      unmappedRoles,
		Roles:              roles,
		Traits:             traits,
		AllowedResourceIDs: allowedResourceIDs,
		RoleSet:            roleSet,
	}, nil
}

type RoleAndUserGetter interface {
	RoleGetter
	UserGetter
}

func AccessInfoFromLocalIdentity(identity tlsca.Identity, access RoleAndUserGetter) (*AccessInfo, error) {
	roles := identity.Groups
	traits := identity.Traits

	// Legacy certs are not encoded with roles or traits,
	// so we fallback to the traits and roles in the backend.
	// empty traits are a valid use case in standard certs,
	// so we only check for whether roles are empty.
	if len(identity.Groups) == 0 {
		u, err := access.GetUser(identity.Username, false)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		log.Warnf("Failed to find roles or traits in x509 identity for %v. Fetching	"+
			"from backend. If the identity provider allows username changes, this can "+
			"potentially allow an attacker to change the role of the existing user.",
			identity.Username)
		roles = u.GetRoles()
		traits = u.GetTraits()
	}

	roleSet, err := FetchRoles(roles, access, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	allowedResourceIDs, err := ResourceIDsFromString(identity.AllowedResourceIDs)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &AccessInfo{
		UnmappedRoles:      roles,
		Roles:              roles,
		Traits:             traits,
		AllowedResourceIDs: allowedResourceIDs,
		RoleSet:            roleSet,
	}, nil
}

func AccessInfoFromRemoteIdentity(identity tlsca.Identity, access RoleGetter, roleMap types.RoleMap) (*AccessInfo, error) {
	// Set internal traits for the remote user. This allows Teleport to work by
	// passing exact logins, Kubernetes users/groups and database users/names
	// to the remote cluster.
	traits := map[string][]string{
		teleport.TraitLogins:     identity.Principals,
		teleport.TraitKubeGroups: identity.KubernetesGroups,
		teleport.TraitKubeUsers:  identity.KubernetesUsers,
		teleport.TraitDBNames:    identity.DatabaseNames,
		teleport.TraitDBUsers:    identity.DatabaseUsers,
	}
	// Prior to Teleport 6.2 no user traits were passed to remote clusters
	// except for the internal ones specified above.
	//
	// To preserve backwards compatible behavior, when applying traits from user
	// identity, make sure to filter out those already present in the map above.
	//
	// This ensures that if e.g. there's a "logins" trait in the root user's
	// identity, it won't overwrite the internal "logins" trait set above
	// causing behavior change.
	for k, v := range identity.Traits {
		if _, ok := traits[k]; !ok {
			traits[k] = v
		}
	}

	unmappedRoles := identity.Groups
	roles, err := MapRoles(roleMap, unmappedRoles)
	if err != nil {
		return nil, trace.AccessDenied("failed to map roles for remote user %q from cluster %q with remote roles %v: %v", identity.Username, identity.TeleportCluster, unmappedRoles, err)
	}
	if len(roles) == 0 {
		return nil, trace.AccessDenied("no roles mapped for remote user %q from cluster %q with remote roles %v", identity.Username, identity.TeleportCluster, unmappedRoles)
	}
	log.Debugf("Mapped roles %v of remote user %q to local roles %v and traits %v.",
		unmappedRoles, identity.Username, roles, traits)

	roleSet, err := FetchRoles(roles, access, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	allowedResourceIDs, err := ResourceIDsFromString(identity.AllowedResourceIDs)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &AccessInfo{
		UnmappedRoles:      roles,
		Roles:              roles,
		Traits:             traits,
		AllowedResourceIDs: allowedResourceIDs,
		RoleSet:            roleSet,
	}, nil
}

func AccessInfoFromUser(user types.User, access RoleGetter) (*AccessInfo, error) {
	roles := user.GetRoles()
	traits := user.GetTraits()
	roleSet, err := FetchRoles(roles, access, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &AccessInfo{
		Roles:   roles,
		Traits:  traits,
		RoleSet: roleSet,
	}, nil
}
