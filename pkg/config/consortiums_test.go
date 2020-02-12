/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config_test

import (
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/pkg/config"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NewConsortiumsGroup", func() {

	var (
		consortiums map[string]*config.Consortium
		mspConfig   *msp.MSPConfig
	)

	BeforeEach(func() {
		consortiums = map[string]*config.Consortium{
			"Consortium1": &config.Consortium{
				Organizations: []*config.Organization{
					&config.Organization{
						Name:     "Org1",
						Policies: createOrgStandardPolicies(),
					},
					&config.Organization{
						Name:     "Org2",
						Policies: createOrgStandardPolicies(),
					},
				},
			},
		}
		mspConfig = &msp.MSPConfig{}
	})

	It("returns a consortiums config group", func() {
		consortiumsGroup, err := config.NewConsortiumsGroup(consortiums, mspConfig)
		Expect(err).NotTo(HaveOccurred())

		// ConsortiumsGroup checks
		Expect(len(consortiumsGroup.Groups)).To(Equal(1))
		Expect(consortiumsGroup.Groups["Consortium1"]).NotTo(BeNil())
		Expect(len(consortiumsGroup.Values)).To(Equal(0))
		Expect(len(consortiumsGroup.Policies)).To(Equal(1))
		Expect(consortiumsGroup.Policies[config.AdminsPolicyKey]).NotTo(BeNil())

		// ConsortiumGroup checks
		Expect(len(consortiumsGroup.Groups["Consortium1"].Groups)).To(Equal(2))
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"]).NotTo(BeNil())
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"]).NotTo(BeNil())
		Expect(len(consortiumsGroup.Groups["Consortium1"].Values)).To(Equal(1))
		Expect(consortiumsGroup.Groups["Consortium1"].Values[config.ChannelCreationPolicyKey]).NotTo(BeNil())
		Expect(len(consortiumsGroup.Groups["Consortium1"].Policies)).To(Equal(0))

		// ConsortiumOrgGroup checks
		Expect(len(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Groups)).To(Equal(0))
		Expect(len(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Groups)).To(Equal(0))
		Expect(len(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Policies)).To(Equal(4))
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Policies[config.ReadersPolicyKey]).NotTo(BeNil())
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Policies[config.WritersPolicyKey]).NotTo(BeNil())
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Policies[config.AdminsPolicyKey]).NotTo(BeNil())
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Policies[config.EndorsementPolicyKey]).NotTo(BeNil())
		Expect(len(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Policies)).To(Equal(4))
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Policies[config.ReadersPolicyKey]).NotTo(BeNil())
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Policies[config.WritersPolicyKey]).NotTo(BeNil())
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Policies[config.AdminsPolicyKey]).NotTo(BeNil())
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Policies[config.EndorsementPolicyKey]).NotTo(BeNil())
		Expect(len(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Values)).To(Equal(1))
		Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Values[config.MSPKey]).NotTo(BeNil())
	})

	When("consortium group policy is empty", func() {
		BeforeEach(func() {
			consortiums["Consortium1"].Organizations[0].Policies = nil
		})

		It("creating policy returns an error", func() {
			consortiumsGroup, err := config.NewConsortiumsGroup(consortiums, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(consortiumsGroup).To(BeNil())
			Expect(err).To(MatchError("error adding policies to consortium org group Org1: no policies defined"))
		})
	})

	When("SkipAsForeign is true", func() {
		BeforeEach(func() {
			consortiums["Consortium1"].Organizations[0].SkipAsForeign = true
			consortiums["Consortium1"].Organizations[1].SkipAsForeign = true
		})

		It("returns a consortiums group with consortium groups that have empty consortium org groups with only mod policy", func() {
			consortiumsGroup, err := config.NewConsortiumsGroup(consortiums, mspConfig)
			Expect(err).ToNot(HaveOccurred())
			Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"]).To(Equal(&common.ConfigGroup{
				ModPolicy: config.AdminsPolicyKey,
				Groups:    make(map[string]*common.ConfigGroup),
				Values:    make(map[string]*common.ConfigValue),
				Policies:  make(map[string]*common.ConfigPolicy),
			}))
			Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"]).To(Equal(&common.ConfigGroup{
				ModPolicy: config.AdminsPolicyKey,
				Groups:    make(map[string]*common.ConfigGroup),
				Values:    make(map[string]*common.ConfigValue),
				Policies:  make(map[string]*common.ConfigPolicy),
			}))
		})
	})
})
