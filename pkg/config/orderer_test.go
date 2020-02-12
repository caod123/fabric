/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config_test

import (
	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
	"github.com/hyperledger/fabric/pkg/config"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NewOrdererGroup", func() {

	var (
		ordererConf *config.Orderer
		mspConfig   *msp.MSPConfig
	)

	BeforeEach(func() {
		ordererConf = &config.Orderer{
			Policies:    createStandardPolicies(),
			OrdererType: config.ConsensusTypeSolo,
			Organizations: []*config.Organization{
				&config.Organization{
					Name:     "Org1",
					ID:       "Org1MSP",
					Policies: createOrgStandardPolicies(),
					MSPType:  "bccsp",
					AnchorPeers: []*config.AnchorPeer{
						&config.AnchorPeer{Host: "host1", Port: 123},
					},
					OrdererEndpoints: []string{
						"localhost:123",
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
		}

		mspConfig = &msp.MSPConfig{}
	})

	It("returns an orderer group config group", func() {
		ordererGroup, err := config.NewOrdererGroup(ordererConf, mspConfig)
		Expect(err).ToNot(HaveOccurred())

		// Orderer group checks
		Expect(len(ordererGroup.Groups)).To(Equal(2))
		Expect(ordererGroup.Groups["Org1"]).NotTo(BeNil())
		Expect(ordererGroup.Groups["Org2"]).NotTo(BeNil())
		Expect(len(ordererGroup.Values)).To(Equal(5))
		Expect(ordererGroup.Values[config.BatchSizeKey]).NotTo(BeNil())
		Expect(ordererGroup.Values[config.BatchTimeoutKey]).NotTo(BeNil())
		Expect(ordererGroup.Values[config.ChannelRestrictionsKey]).NotTo(BeNil())
		Expect(ordererGroup.Values[config.CapabilitiesKey]).NotTo(BeNil())
		Expect(ordererGroup.Values[config.ConsensusTypeKey]).NotTo(BeNil())
		var consensusType orderer.ConsensusType
		err = proto.Unmarshal(ordererGroup.Values[config.ConsensusTypeKey].Value, &consensusType)
		Expect(err).NotTo(HaveOccurred())
		Expect(consensusType.Type).To(Equal(config.ConsensusTypeSolo))
		Expect(len(ordererGroup.Policies)).To(Equal(6))
		Expect(ordererGroup.Policies[config.AdminsPolicyKey]).NotTo(BeNil())
		Expect(ordererGroup.Policies[config.ReadersPolicyKey]).NotTo(BeNil())
		Expect(ordererGroup.Policies[config.WritersPolicyKey]).NotTo(BeNil())
		Expect(ordererGroup.Policies[config.EndorsementPolicyKey]).NotTo(BeNil())
		Expect(ordererGroup.Policies[config.BlockValidationPolicyKey]).NotTo(BeNil())

		// Orderer org group check
		Expect(len(ordererGroup.Groups["Org1"].Groups)).To(Equal(0))
		Expect(len(ordererGroup.Groups["Org1"].Values)).To(Equal(2))
		Expect(ordererGroup.Groups["Org1"].Values[config.MSPKey]).NotTo(BeNil())
		Expect(ordererGroup.Groups["Org1"].Values[config.EndpointsKey]).NotTo(BeNil())
		Expect(len(ordererGroup.Groups["Org1"].Policies)).To(Equal(4))
		Expect(ordererGroup.Groups["Org1"].Policies[config.AdminsPolicyKey]).NotTo(BeNil())
		Expect(ordererGroup.Groups["Org1"].Policies[config.ReadersPolicyKey]).NotTo(BeNil())
		Expect(ordererGroup.Groups["Org1"].Policies[config.WritersPolicyKey]).NotTo(BeNil())
		Expect(ordererGroup.Groups["Org1"].Policies[config.EndorsementPolicyKey]).NotTo(BeNil())
		Expect(len(ordererGroup.Groups["Org2"].Groups)).To(Equal(0))
		Expect(len(ordererGroup.Groups["Org2"].Values)).To(Equal(1))
		Expect(ordererGroup.Groups["Org2"].Values[config.MSPKey]).NotTo(BeNil())
		Expect(len(ordererGroup.Groups["Org2"].Policies)).To(Equal(4))
		Expect(ordererGroup.Groups["Org2"].Policies[config.AdminsPolicyKey]).NotTo(BeNil())
		Expect(ordererGroup.Groups["Org2"].Policies[config.ReadersPolicyKey]).NotTo(BeNil())
		Expect(ordererGroup.Groups["Org2"].Policies[config.WritersPolicyKey]).NotTo(BeNil())
		Expect(ordererGroup.Groups["Org2"].Policies[config.EndorsementPolicyKey]).NotTo(BeNil())
	})

	When("orderer type is kafka", func() {
		BeforeEach(func() {
			ordererConf.OrdererType = config.ConsensusTypeKafka
		})
		It("returns an orderer group config group", func() {
			ordererGroup, err := config.NewOrdererGroup(ordererConf, mspConfig)
			Expect(err).ToNot(HaveOccurred())

			// Orderer group checks
			Expect(len(ordererGroup.Groups)).To(Equal(2))
			Expect(ordererGroup.Groups["Org1"]).NotTo(BeNil())
			Expect(ordererGroup.Groups["Org2"]).NotTo(BeNil())
			Expect(len(ordererGroup.Values)).To(Equal(6))
			Expect(ordererGroup.Values[config.BatchSizeKey]).NotTo(BeNil())
			Expect(ordererGroup.Values[config.BatchTimeoutKey]).NotTo(BeNil())
			Expect(ordererGroup.Values[config.ChannelRestrictionsKey]).NotTo(BeNil())
			Expect(ordererGroup.Values[config.CapabilitiesKey]).NotTo(BeNil())
			Expect(ordererGroup.Values[config.ConsensusTypeKey]).NotTo(BeNil())
			var consensusType orderer.ConsensusType
			err = proto.Unmarshal(ordererGroup.Values[config.ConsensusTypeKey].Value, &consensusType)
			Expect(err).NotTo(HaveOccurred())
			Expect(consensusType.Type).To(Equal(config.ConsensusTypeKafka))
			Expect(len(ordererGroup.Policies)).To(Equal(6))
			Expect(ordererGroup.Policies[config.AdminsPolicyKey]).NotTo(BeNil())
			Expect(ordererGroup.Policies[config.ReadersPolicyKey]).NotTo(BeNil())
			Expect(ordererGroup.Policies[config.WritersPolicyKey]).NotTo(BeNil())
			Expect(ordererGroup.Policies[config.EndorsementPolicyKey]).NotTo(BeNil())
			Expect(ordererGroup.Policies[config.BlockValidationPolicyKey]).NotTo(BeNil())
		})
	})

	When("orderer type is ConsensusTypeEtcdRaft", func() {
		BeforeEach(func() {
			ordererConf.OrdererType = config.ConsensusTypeEtcdRaft
			ordererConf.EtcdRaft = &etcdraft.ConfigMetadata{}
		})

		It("returns an orderer group config group", func() {
			ordererGroup, err := config.NewOrdererGroup(ordererConf, mspConfig)
			Expect(err).NotTo(HaveOccurred())

			// Orderer group check
			Expect(len(ordererGroup.Groups)).To(Equal(2))
			Expect(ordererGroup.Groups["Org1"]).NotTo(BeNil())
			Expect(ordererGroup.Groups["Org2"]).NotTo(BeNil())
			Expect(len(ordererGroup.Values)).To(Equal(5))
			Expect(ordererGroup.Values[config.BatchSizeKey]).NotTo(BeNil())
			Expect(ordererGroup.Values[config.BatchTimeoutKey]).NotTo(BeNil())
			Expect(ordererGroup.Values[config.ChannelRestrictionsKey]).NotTo(BeNil())
			Expect(ordererGroup.Values[config.CapabilitiesKey]).NotTo(BeNil())
			Expect(ordererGroup.Values[config.ConsensusTypeKey]).NotTo(BeNil())
			var consensusType orderer.ConsensusType
			err = proto.Unmarshal(ordererGroup.Values[config.ConsensusTypeKey].Value, &consensusType)
			Expect(err).NotTo(HaveOccurred())
			Expect(consensusType.Type).To(Equal(config.ConsensusTypeEtcdRaft))
			Expect(len(ordererGroup.Policies)).To(Equal(6))
			Expect(ordererGroup.Policies[config.AdminsPolicyKey]).NotTo(BeNil())
			Expect(ordererGroup.Policies[config.ReadersPolicyKey]).NotTo(BeNil())
			Expect(ordererGroup.Policies[config.WritersPolicyKey]).NotTo(BeNil())
			Expect(ordererGroup.Policies[config.EndorsementPolicyKey]).NotTo(BeNil())
			Expect(ordererGroup.Policies[config.BlockValidationPolicyKey]).NotTo(BeNil())
		})

		When("EtcdRaft config is not set", func() {
			BeforeEach(func() {
				ordererConf.EtcdRaft = nil
			})

			It("returns an error", func() {
				ordererGroup, err := config.NewOrdererGroup(ordererConf, mspConfig)
				Expect(ordererGroup).To(BeNil())
				Expect(err).To(MatchError("EtcdRaft not set for consensus type etcdraft"))
			})
		})
	})

	When("orderer group policy is empty", func() {
		BeforeEach(func() {
			ordererConf = &config.Orderer{}
			ordererConf.Policies = nil
		})

		It("returns an error", func() {
			ordererGroup, err := config.NewOrdererGroup(ordererConf, mspConfig)
			Expect(ordererGroup).To(BeNil())
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
			ordererConf = &config.Orderer{
				OrdererType: config.ConsensusTypeEtcdRaft,
				EtcdRaft:    md,
				Policies:    createStandardPolicies(),
			}
		})

		It("returns an error", func() {
			ordererGroup, err := config.NewOrdererGroup(ordererConf, mspConfig)
			Expect(ordererGroup).To(BeNil())
			Expect(err).To(MatchError("cannot marshal metadata for orderer type etcdraft: " +
				"cannot load client cert for consenter node-1.example.com:7050: open testdata/tls-client-1.pem: no such file or directory"))
		})
	})

	When("orderer type is unknown", func() {
		BeforeEach(func() {
			ordererConf = &config.Orderer{
				OrdererType: "fakeOrdererType",
				Policies:    createStandardPolicies(),
			}
		})

		It("returns an error", func() {
			ordererGroup, err := config.NewOrdererGroup(ordererConf, mspConfig)
			Expect(ordererGroup).To(BeNil())
			Expect(err).To(MatchError("unknown orderer type, fakeOrdererType"))
		})
	})

	When("adding policies to orderer org group fails", func() {
		BeforeEach(func() {
			ordererConf = &config.Orderer{
				OrdererType: config.ConsensusTypeSolo,
				Policies:    createStandardPolicies(),
				Organizations: []*config.Organization{
					&config.Organization{Name: "fakeO1"},
				},
			}
		})

		It("returns an error", func() {
			ordererGroup, err := config.NewOrdererGroup(ordererConf, mspConfig)
			Expect(ordererGroup).To(BeNil())
			Expect(err).To(MatchError("failed to create orderer org fakeO1: error adding policies " +
				"to orderer org group fakeO1: no policies defined"))
		})
	})
})
