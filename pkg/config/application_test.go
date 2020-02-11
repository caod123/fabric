/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
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
		}
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
