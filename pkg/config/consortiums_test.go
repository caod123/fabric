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

var _ = Describe("NewConsortiumsGroup", func() {

	var (
		consortiums map[string]*Consortium
		mspConfig   *msp.MSPConfig
	)

	BeforeEach(func() {
		consortiums = map[string]*Consortium{
			"consortiumName": &Consortium{
				Organizations: []*Organization{
					&Organization{
						Name:     "C1",
						Policies: CreateStandardPolicies(),
					},
				},
			},
		}
	})

	When("consortium group policy is empty", func() {

		BeforeEach(func() {
			consortiums["consortiumName"].Organizations[0].Policies = nil
		})

		It("creating policy returns an error", func() {
			configGrp, err := NewConsortiumsGroup(consortiums, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(configGrp).To(BeNil())
			Expect(err).To(MatchError("error adding policies to consortium org group C1: no policies defined"))
		})
	})

})
