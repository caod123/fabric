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

var _ = Describe("NewApplicationGroup", func() {

	var (
		application *config.Application
		mspConfig   *msp.MSPConfig
	)

	BeforeEach(func() {
		application = &config.Application{
			Policies: createStandardPolicies(),
			Organizations: []*config.Organization{
				&config.Organization{
					Name:     "Org1",
					ID:       "Org1MSP",
					Policies: createOrgStandardPolicies(),
					MSPType:  "bccsp",
					AnchorPeers: []*config.AnchorPeer{
						&config.AnchorPeer{Host: "host1", Port: 123},
					},
				},
				&config.Organization{
					Name:     "Org2",
					ID:       "Org2MSP",
					Policies: createOrgStandardPolicies(),
					MSPType:  "bccsp",
					AnchorPeers: []*config.AnchorPeer{
						&config.AnchorPeer{Host: "host2", Port: 123},
					},
				},
			},
			Capabilities: map[string]bool{
				"V1_3": true,
			},
			ACLs: map[string]string{
				"acl1": "hi",
			},
		}

		mspConfig = &msp.MSPConfig{}
	})

	It("returns a config group", func() {
		applicationGroup, err := config.NewApplicationGroup(application, mspConfig)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(applicationGroup.Policies)).To(Equal(5))
		Expect(applicationGroup.Policies["Admins"]).NotTo(BeNil())
		Expect(applicationGroup.Policies["Readers"]).NotTo(BeNil())
		Expect(applicationGroup.Policies["Writers"]).NotTo(BeNil())
		Expect(len(applicationGroup.Groups)).To(Equal(2))
		Expect(applicationGroup.Groups["Org1"]).NotTo(BeNil())
		Expect(applicationGroup.Groups["Org2"]).NotTo(BeNil())
		Expect(len(applicationGroup.Values)).To(Equal(2))
		Expect(applicationGroup.Values["ACLs"]).NotTo(BeNil())
		Expect(applicationGroup.Values["Capabilities"]).NotTo(BeNil())
	})

	When("application group policy is empty", func() {
		BeforeEach(func() {
			application.Policies = nil
		})

		It("returns an error", func() {
			configGrp, err := config.NewApplicationGroup(application, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(configGrp).To(BeNil())
			Expect(err).To(MatchError("error adding policies to application group: no policies defined"))
		})
	})

	When("adding policies to application group", func() {
		BeforeEach(func() {
			application.Organizations = []*config.Organization{
				&config.Organization{Name: "AppName1"},
			}
		})

		It("returns an error", func() {
			configGrp, err := config.NewApplicationGroup(application, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(configGrp).To(BeNil())
			Expect(err).To(MatchError("failed to create application " +
				"org AppName1: error adding policies to application org group AppName1: no policies defined"))
		})
	})

	When("SkipAsForeign is true", func() {
		BeforeEach(func() {
			application.Organizations[0].SkipAsForeign = true
			application.Organizations[1].SkipAsForeign = true
		})

		It("returns an empty org group with only mod policy", func() {
			applicationGroup, err := config.NewApplicationGroup(application, mspConfig)
			Expect(err).ToNot(HaveOccurred())
			Expect(applicationGroup.Groups["Org1"]).To(Equal(&common.ConfigGroup{
				ModPolicy: config.AdminsPolicyKey,
				Groups:    make(map[string]*common.ConfigGroup),
				Values:    make(map[string]*common.ConfigValue),
				Policies:  make(map[string]*common.ConfigPolicy),
			}))
			Expect(applicationGroup.Groups["Org2"]).To(Equal(&common.ConfigGroup{
				ModPolicy: config.AdminsPolicyKey,
				Groups:    make(map[string]*common.ConfigGroup),
				Values:    make(map[string]*common.ConfigValue),
				Policies:  make(map[string]*common.ConfigPolicy),
			}))
		})
	})
})
