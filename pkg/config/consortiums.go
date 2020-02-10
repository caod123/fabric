/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"fmt"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
)

// AcceptAllPolicy always evaluates to true
var AcceptAllPolicy *common.SignaturePolicyEnvelope

// Consortium represents a group of organizations which may create channels
// with each other
type Consortium struct {
	Organizations []*Organization
}

// Consortiums

// NewConsortiumsGroup returns the consortiums component of the channel configuration.  This element is only defined for the ordering system channel.
// It sets the mod_policy for all elements to "/Channel/Orderer/Admins".
func NewConsortiumsGroup(conf map[string]*Consortium, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	consortiumsGroup := NewConfigGroup()

	// QUESTION: How should we set this? the original impl did it globally...
	AcceptAllPolicy = Envelope(NOutOf(0, []*common.SignaturePolicy{}), [][]byte{})
	// This policy is not referenced anywhere, it is only used as part of the implicit meta policy rule at the channel level, so this setting
	// effectively degrades control of the ordering system channel to the ordering admins
	addPolicy(consortiumsGroup, SignaturePolicy(AdminsPolicyKey, AcceptAllPolicy), ordererAdminsPolicyName)

	for consortiumName, consortium := range conf {
		var err error
		consortiumsGroup.Groups[consortiumName], err = NewConsortiumGroup(consortium, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create consortium, %s error: %v", consortiumName, err)
		}
	}

	consortiumsGroup.ModPolicy = ordererAdminsPolicyName
	return consortiumsGroup, nil
}

// NewConsortiumGroup ...
func NewConsortiumGroup(conf *Consortium, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	consortiumGroup := NewConfigGroup()

	for _, org := range conf.Organizations {
		var err error
		consortiumGroup.Groups[org.Name], err = NewConsortiumOrgGroup(org, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create consortium org %v", err)
		}
	}

	addValue(consortiumGroup, ChannelCreationPolicyValue(ImplicitMetaAnyPolicy(AdminsPolicyKey).Value()), ordererAdminsPolicyName)

	consortiumGroup.ModPolicy = ordererAdminsPolicyName
	return consortiumGroup, nil
}

// NewConsortiumOrgGroup returns an org component of the channel configuration.  It defines the crypto material for the
// organization (its MSP).  It sets the mod_policy of all elements to "Admins".
func NewConsortiumOrgGroup(conf *Organization, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	consortiumsOrgGroup := NewConfigGroup()
	consortiumsOrgGroup.ModPolicy = AdminsPolicyKey

	if conf.SkipAsForeign {
		return consortiumsOrgGroup, nil
	}

	if err := AddPolicies(consortiumsOrgGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies to consortiums org group '%s' error: %v", conf.Name, err)
	}

	addValue(consortiumsOrgGroup, MSPValue(mspConfig), AdminsPolicyKey)

	return consortiumsOrgGroup, nil
}

// ConsortiumValue returns the config definition for the consortium name.
// It is a value for the channel group.
func ConsortiumValue(name string) *StandardConfigValue {
	return &StandardConfigValue{
		key: ConsortiumKey,
		value: &common.Consortium{
			Name: name,
		},
	}
}

// ChannelCreationPolicyValue returns the config definition for a consortium's channel creation policy
// It is a value for the /Channel/Consortiums/*/*.
func ChannelCreationPolicyValue(policy *common.Policy) *StandardConfigValue {
	return &StandardConfigValue{
		key:   ChannelCreationPolicyKey,
		value: policy,
	}
}

// Envelope builds an envelope message embedding a SignaturePolicy
func Envelope(policy *common.SignaturePolicy, identities [][]byte) *common.SignaturePolicyEnvelope {
	ids := make([]*msp.MSPPrincipal, len(identities))
	for i := range ids {
		ids[i] = &msp.MSPPrincipal{PrincipalClassification: msp.MSPPrincipal_IDENTITY, Principal: identities[i]}
	}

	return &common.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policy,
		Identities: ids,
	}
}

// NOutOf creates a policy which requires N out of the slice of policies to evaluate to true
func NOutOf(n int32, policies []*common.SignaturePolicy) *common.SignaturePolicy {
	return &common.SignaturePolicy{
		Type: &common.SignaturePolicy_NOutOf_{
			NOutOf: &common.SignaturePolicy_NOutOf{
				N:     n,
				Rules: policies,
			},
		},
	}
}
