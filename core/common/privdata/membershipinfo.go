/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package privdata

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/protos/common"
	mspp "github.com/hyperledger/fabric/protos/msp"
	"github.com/pkg/errors"
)

var logger = flogging.MustGetLogger("common.privdata")

// MembershipProvider can be used to check whether a peer is eligible to a collection or not
type MembershipProvider struct {
	mspID                       string
	selfSignedData              common.SignedData
	IdentityDeserializerFactory func(chainID string) msp.IdentityDeserializer
}

// NewMembershipInfoProvider returns MembershipProvider
func NewMembershipInfoProvider(mspID string, selfSignedData common.SignedData,
	identityDeserializerFunc func(chainID string) msp.IdentityDeserializer) *MembershipProvider {
	return &MembershipProvider{mspID: mspID, selfSignedData: selfSignedData, IdentityDeserializerFactory: identityDeserializerFunc}
}

// AmMemberOf checks whether the current peer is a member of the given collection config.
// If getPolicy returns an error, it will drop the error and return false - same as a RejectAll policy.
func (m *MembershipProvider) AmMemberOf(channelName string,
	collectionPolicyConfig *common.CollectionPolicyConfig) (bool, error) {
	deserializer := m.IdentityDeserializerFactory(channelName)

	// Do a simple check to see if the mspid matches any principal identities in the SignaturePolicy
	if collectionPolicyConfig.GetSignaturePolicy() != nil {
		memberOrgs, err := getMemberOrgs(collectionPolicyConfig.GetSignaturePolicy().GetIdentities(), deserializer)
		if err != nil {
			logger.Errorf("Failed getting member orgs from MSP Principals: %s", err)
			return false, nil
		}
		for _, member := range memberOrgs {
			if m.mspID == member {
				return true, nil
			}
		}
		return false, nil
	}

	// Fall back to default access policy evaluation otherwise
	accessPolicy, err := getPolicy(collectionPolicyConfig, deserializer)
	if err != nil {
		// drop the error and return false - same as reject all policy
		logger.Errorf("Reject all due to error getting policy: %s", err)
		return false, nil
	}

	if err := accessPolicy.Evaluate([]*common.SignedData{&m.selfSignedData}); err != nil {
		return false, nil
	}

	return true, nil
}

// Returns a list of member orgs from a list of MSPPrincipals
func getMemberOrgs(identities []*mspp.MSPPrincipal, deserializer msp.IdentityDeserializer) ([]string, error) {
	memberOrgs := []string{}

	// get member org MSP IDs from the envelope
	for _, principal := range identities {
		switch principal.PrincipalClassification {
		case mspp.MSPPrincipal_ROLE:
			// Principal contains the msp role
			mspRole := &mspp.MSPRole{}
			err := proto.Unmarshal(principal.Principal, mspRole)
			if err != nil {
				return memberOrgs, errors.Wrap(err, "Could not unmarshal MSPRole from principal")
			}
			memberOrgs = append(memberOrgs, mspRole.MspIdentifier)
		case mspp.MSPPrincipal_IDENTITY:
			principalId, err := deserializer.DeserializeIdentity(principal.Principal)
			if err != nil {
				return memberOrgs, errors.Wrap(err, "Invalid identity principal, not a certificate")
			}
			memberOrgs = append(memberOrgs, principalId.GetMSPIdentifier())
		case mspp.MSPPrincipal_ORGANIZATION_UNIT:
			OU := &mspp.OrganizationUnit{}
			err := proto.Unmarshal(principal.Principal, OU)
			if err != nil {
				return memberOrgs, errors.Wrap(err, "Could not unmarshal OrganizationUnit from principal")
			}
			memberOrgs = append(memberOrgs, OU.MspIdentifier)
		default:
			return memberOrgs, errors.New(fmt.Sprintf("Invalid principal type %d", int32(principal.PrincipalClassification)))
		}
	}
	return memberOrgs, nil
}
