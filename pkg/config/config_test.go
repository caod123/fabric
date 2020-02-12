/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Question: Put these test helper functions in separate file?
func CreateStandardPolicies() map[string]*Policy {
	return map[string]*Policy{
		"Readers": {
			Type: "ImplicitMeta",
			Rule: "ANY Readers",
		},
		"Writers": {
			Type: "ImplicitMeta",
			Rule: "ANY Writers",
		},
		"Admins": {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Admins",
		},
		"LifecycleEndorsement": {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Endorsement",
		},
		"Endorsement": {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Endorsement",
		},
	}
}

// Question: Put these test helper functions in separate file?
func CreateOrgStandardPolicies() map[string]*Policy {
	return map[string]*Policy{
		"Readers": {
			Type: "ImplicitMeta",
			Rule: "ANY Readers",
		},
		"Writers": {
			Type: "ImplicitMeta",
			Rule: "ANY Writers",
		},
		"Admins": {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Admins",
		},
		"Endorsement": {
			Type: "ImplicitMeta",
			Rule: "ANY Endorsement",
		},
	}
}

var _ = Describe("CreateChannelTx", func() {

	var (
		testDir   string
		profile   *Profile
		mspConfig *MSPConfig
	)

	BeforeEach(func() {
		var err error
		testDir, err = ioutil.TempDir("", "config")
		Expect(err).NotTo(HaveOccurred())

		profile = &Profile{
			ChannelID:  "testchannel",
			Consortium: "SampleConsortium",
			Application: &Application{
				Policies: CreateStandardPolicies(),
				Organizations: []*Organization{
					&Organization{
						Name:     "Org1",
						ID:       "Org1MSP",
						Policies: CreateOrgStandardPolicies(),
						MSPType:  "bccsp",
					},
					&Organization{
						Name:     "Org2",
						ID:       "Org2MSP",
						Policies: CreateOrgStandardPolicies(),
						MSPType:  "bccsp",
					},
				},
				Capabilities: map[string]bool{
					"V1_3": true,
				},
			},
			Capabilities: map[string]bool{"V2_0": true},
			Policies:     CreateStandardPolicies(),
		}
		mspConfig = &MSPConfig{}
	})

	AfterEach(func() {
		os.RemoveAll(testDir)
	})

	When("channel is not specified in config", func() {
		BeforeEach(func() {
			profile = nil
		})

		It("returns an error", func() {
			blk, err := CreateChannelTx(profile, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(blk).To(BeNil())
			Expect(err).To(MatchError("failed to create channel tx because profile is empty"))
		})

	})

	When("channel ID is not specified in config", func() {
		BeforeEach(func() {
			profile.ChannelID = ""
		})

		It("returns an error", func() {
			blk, err := CreateChannelTx(profile, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(blk).To(BeNil())
			Expect(err).To(MatchError("failed to create channel tx because channel ID is empty"))
		})
	})

	When("generating config template", func() {

		When("policy is empty", func() {

			BeforeEach(func() {
				profile.Policies = nil
			})

			It("returns an error", func() {
				blk, err := CreateChannelTx(profile, mspConfig)
				Expect(err).To(HaveOccurred())
				Expect(blk).To(BeNil())
				Expect(err).To(MatchError("could not generate default config template: error adding policies to channel group: no policies defined"))
			})
		})
	})

})
