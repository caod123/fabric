/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NewApplicationGroup", func() {

	var (
		application *Application
		mspConfig   *msp.MSPConfig
	)

	BeforeEach(func() {
		application = &Application{
			Policies: CreateStandardPolicies(),
			Organizations: []*Organization{
				&Organization{
					Name:     "Org1",
					ID:       "Org1MSP",
					Policies: CreateOrgStandardPolicies(),
					MSPType:  "bccsp",
					AnchorPeers: []*AnchorPeer{
						&AnchorPeer{Host: "host1", Port: 123},
					},
				},
				&Organization{
					Name:     "Org2",
					ID:       "Org2MSP",
					Policies: CreateOrgStandardPolicies(),
					MSPType:  "bccsp",
					AnchorPeers: []*AnchorPeer{
						&AnchorPeer{Host: "host2", Port: 123},
					},
				},
			},
			Capabilities: map[string]bool{
				"V1_3": true,
			},
		}
		mspConfig = &msp.MSPConfig{}
	})

	PIt("returns an config group", func() {
		configGrps, err := NewApplicationGroup(application, mspConfig)
		Expect(err).ToNot(HaveOccurred())
		Expect(configGrps).To(Equal(common.ConfigGroup{}))
	})

	FWhen("SkipAsForeign is true", func() {
		BeforeEach(func() {
			application.Organizations[0].SkipAsForeign = true
			application.Organizations[1].SkipAsForeign = true
		})

		It("returns an empty org group with only mod policy", func() {
			configGrps, err := NewApplicationGroup(application, mspConfig)
			Expect(err).ToNot(HaveOccurred())
			Expect(*configGrps.Groups["Org1"]).To(BeIdenticalTo(common.ConfigGroup{
				ModPolicy: AdminsPolicyKey,
			}))
			Expect(configGrps.Groups["Org2"]).To(Equal(common.ConfigGroup{
				ModPolicy: AdminsPolicyKey,
			}))
		})
	})

	When("application group policy is empty", func() {
		BeforeEach(func() {
			application.Policies = nil
		})

		It("returns an error", func() {
			configGrp, err := NewApplicationGroup(application, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(configGrp).To(BeNil())
			Expect(err).To(MatchError("error adding policies to application group: no policies defined"))
		})
	})

	When("adding policies to application group", func() {
		BeforeEach(func() {
			application.Organizations = []*Organization{
				&Organization{Name: "AppName1"},
			}
		})

		It("returns an error", func() {
			configGrp, err := NewApplicationGroup(application, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(configGrp).To(BeNil())
			Expect(err).To(MatchError("failed to create application " +
				"org AppName1: error adding policies to application org group AppName1: no policies defined"))
		})
	})

})
