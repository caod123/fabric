/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NewOrdererGroup", func() {

	var (
		ordererConf *Orderer
		mspConfig   *msp.MSPConfig
	)

	BeforeEach(func() {
		ordererConf = &Orderer{}
	})

	When("orderer group policy is empty", func() {

		BeforeEach(func() {
			ordererConf = &Orderer{}
			ordererConf.Policies = nil
		})

		It("returns an error", func() {
			configGrp, err := NewOrdererGroup(ordererConf, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(configGrp).To(BeNil())
			Expect(err).To(MatchError("error adding policies to orderer group: no policies defined"))
		})
	})

	When("marshalling etcdraft metadata for orderer group fails", func() {

		BeforeEach(func() {
			md := &etcdraft.ConfigMetadata{
				Consenters: []*etcdraft.Consenter{
					{
						Host:          "node-1.example.com",
						Port:          7050,
						ClientTlsCert: []byte("testdata/tls-client-1.pem"),
						ServerTlsCert: []byte("testdata/tls-server-1.pem"),
					},
					{
						Host:          "node-2.example.com",
						Port:          7050,
						ClientTlsCert: []byte("testdata/tls-client-2.pem"),
						ServerTlsCert: []byte("testdata/tls-server-2.pem"),
					},
					{
						Host:          "node-3.example.com",
						Port:          7050,
						ClientTlsCert: []byte("testdata/tls-client-3.pem"),
						ServerTlsCert: []byte("testdata/tls-server-3.pem"),
					},
				},
			}
			ordererConf = &Orderer{
				OrdererType: ConsensusTypeEtcdRaft,
				EtcdRaft:    md,
				Policies:    CreateStandardPolicies(),
			}
		})

		It("returns an error", func() {
			configGrp, err := NewOrdererGroup(ordererConf, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(configGrp).To(BeNil())
			Expect(err).To(MatchError("cannot marshal metadata for orderer type etcdraft: " +
				"cannot load client cert for consenter node-1.example.com:7050: open testdata/tls-client-1.pem: no such file or directory"))
		})
	})

	When("orderer type is unknown", func() {

		BeforeEach(func() {
			ordererConf = &Orderer{
				OrdererType: "fakeOrdererType",
				Policies:    CreateStandardPolicies(),
			}
		})

		It("returns an error", func() {
			configGrp, err := NewOrdererGroup(ordererConf, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(configGrp).To(BeNil())
			Expect(err).To(MatchError("unknown orderer type, fakeOrdererType"))
		})
	})

	When("adding policies to orderer org group fails", func() {

		BeforeEach(func() {
			ordererConf = &Orderer{
				OrdererType: ConsensusTypeSolo,
				Policies:    CreateStandardPolicies(),
				Organizations: []*Organization{
					&Organization{Name: "fakeO1"},
				},
			}
		})

		It("returns an error", func() {
			configGrp, err := NewOrdererGroup(ordererConf, mspConfig)
			Expect(err).To(HaveOccurred())
			Expect(configGrp).To(BeNil())
			Expect(err).To(MatchError("failed to create orderer org fakeO1: error adding policies " +
				"to orderer org group fakeO1: no policies defined"))
		})
	})

})
