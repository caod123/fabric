/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config_test

import (
	"io/ioutil"
	"os"

	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/pkg/config"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CreateChannelTx", func() {
	var (
		testDir   string
		profile   *config.Profile
		mspConfig *msp.FabricMSPConfig
	)

	BeforeEach(func() {
		var err error
		testDir, err = ioutil.TempDir("", "config")
		Expect(err).NotTo(HaveOccurred())

		profile = &config.Profile{
			ChannelID:  "testchannel",
			Consortium: "SampleConsortium",
			Application: &config.Application{
				Policies: createStandardPolicies(),
				Organizations: []*config.Organization{
					&config.Organization{
						Name:     "Org1",
						ID:       "Org1MSP",
						Policies: createOrgStandardPolicies(),
						MSPType:  "bccsp",
					},
					&config.Organization{
						Name:     "Org2",
						ID:       "Org2MSP",
						Policies: createOrgStandardPolicies(),
						MSPType:  "bccsp",
					},
				},
				Capabilities: map[string]bool{
					"V1_3": true,
				},
			},
			Capabilities: map[string]bool{"V2_0": true},
			Policies:     createStandardPolicies(),
		}

		mspConfig = &msp.FabricMSPConfig{}
	})

	AfterEach(func() {
		os.RemoveAll(testDir)
	})

	It("returns an envelope", func() {
		env, err := config.CreateChannelTx(profile, mspConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(env).NotTo(BeNil())
	})

	When("creating the default config template fails", func() {
		BeforeEach(func() {
			profile.Policies = nil
		})

		It("returns an error", func() {
			env, err := config.CreateChannelTx(profile, mspConfig)
			Expect(env).To(BeNil())
			Expect(err).To(MatchError("could not generate default config template: error adding policies to channel group: no policies defined"))
		})
	})

	When("channel is not specified in config", func() {
		BeforeEach(func() {
			profile = nil
		})

		It("returns an error", func() {
			env, err := config.CreateChannelTx(profile, mspConfig)
			Expect(env).To(BeNil())
			Expect(err).To(MatchError("failed to create channel tx because profile is empty"))
		})
	})

	When("channel ID is not specified in config", func() {
		BeforeEach(func() {
			profile.ChannelID = ""
		})

		It("returns an error", func() {
			env, err := config.CreateChannelTx(profile, mspConfig)
			Expect(env).To(BeNil())
			Expect(err).To(MatchError("failed to create channel tx because channel ID is empty"))
		})
	})

	When("generating config template", func() {
		When("policy is empty", func() {
			BeforeEach(func() {
				profile.Policies = nil
			})

			It("returns an error", func() {
				env, err := config.CreateChannelTx(profile, mspConfig)
				Expect(err).To(HaveOccurred())
				Expect(env).To(BeNil())
				Expect(err).To(MatchError("could not generate default config template: error adding policies to channel group: no policies defined"))
			})
		})
	})
})

func createStandardPolicies() map[string]*config.Policy {
	return map[string]*config.Policy{
		config.ReadersPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "ANY Readers",
		},
		config.WritersPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		config.AdminsPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "MAJORITY Admins",
		},
		config.LifecycleEndorsementPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "MAJORITY Endorsement",
		},
		config.EndorsementPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "MAJORITY Endorsement",
		},
	}
}

func createOrgStandardPolicies() map[string]*config.Policy {
	return map[string]*config.Policy{
		config.ReadersPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "ANY Readers",
		},
		config.WritersPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		config.AdminsPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "MAJORITY Admins",
		},
		config.EndorsementPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "ANY Endorsement",
		},
	}
}
