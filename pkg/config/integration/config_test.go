/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config_test

import (
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	"github.com/hyperledger/fabric/pkg/config"
)

var _ = Describe("CreateChannelTx", func() {
	var (
		testDir   string
		network   *nwo.Network
		profile   *config.Profile
		mspConfig *msp.FabricMSPConfig
	)

	BeforeEach(func() {
		var err error
		testDir, err = ioutil.TempDir("", "config")
		Expect(err).NotTo(HaveOccurred())

		network = nwo.New(nwo.BasicSolo(), testDir, nil, StartPort(), components)

		network.GenerateConfigTree()

		network.Bootstrap()

		profile = &config.Profile{
			ChannelID:  "testchannel",
			Consortium: "SampleConsortium",
			Application: &config.Application{
				Policies: createStandardPolicies(),
				Organizations: []*config.Organization{
					{
						Name:     "Org1",
						ID:       "Org1MSP",
						Policies: createOrgStandardPolicies(),
						MSPType:  "bccsp",
						MSPDir:   network.PeerOrgMSPDir(network.Organization("Org1")),
					},
					{
						Name:     "Org2",
						ID:       "Org2MSP",
						Policies: createOrgStandardPolicies(),
						MSPType:  "bccsp",
						MSPDir:   network.PeerOrgMSPDir(network.Organization("Org2")),
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
		if network != nil {
			network.Cleanup()
		}
		os.RemoveAll(testDir)
	})

	It("creates envelope", func() {
		createChannelTxPath := network.CreateChannelTxPath(profile.ChannelID)

		envelope, err := config.CreateChannelTx(profile, mspConfig)
		Expect(err).ToNot(HaveOccurred())
		Expect(envelope).ToNot(BeNil())

		By("using configtxgen to create a create channel transaction")
		sess, err := network.ConfigTxGen(commands.CreateChannelTx{
			ChannelID:             profile.ChannelID,
			Profile:               "TwoOrgsChannel",
			ConfigPath:            testDir,
			OutputCreateChannelTx: createChannelTxPath,
		})
		Expect(err).NotTo(HaveOccurred())
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))

		configTxBytes, err := ioutil.ReadFile(createChannelTxPath)
		Expect(err).ToNot(HaveOccurred())

		expectedEnvelope := common.Envelope{}
		err = proto.Unmarshal(configTxBytes, &expectedEnvelope)
		Expect(err).NotTo(HaveOccurred())

		expectedPayload := common.Payload{}
		err = proto.Unmarshal(expectedEnvelope.Payload, &expectedPayload)
		Expect(err).NotTo(HaveOccurred())

		expectedHeader := common.ChannelHeader{}
		err = proto.Unmarshal(expectedPayload.Header.ChannelHeader, &expectedHeader)
		Expect(err).NotTo(HaveOccurred())

		expectedData := common.ConfigUpdateEnvelope{}
		err = proto.Unmarshal(expectedPayload.Data, &expectedData)
		Expect(err).NotTo(HaveOccurred())

		expectedConfigUpdate := common.ConfigUpdate{}
		err = proto.Unmarshal(expectedData.ConfigUpdate, &expectedConfigUpdate)
		Expect(err).NotTo(HaveOccurred())

		actualPayload := common.Payload{}
		err = proto.Unmarshal(envelope.Payload, &actualPayload)
		Expect(err).NotTo(HaveOccurred())

		actualHeader := common.ChannelHeader{}
		err = proto.Unmarshal(actualPayload.Header.ChannelHeader, &actualHeader)
		Expect(err).NotTo(HaveOccurred())

		actualData := common.ConfigUpdateEnvelope{}
		err = proto.Unmarshal(actualPayload.Data, &actualData)
		Expect(err).NotTo(HaveOccurred())

		actualConfigUpdate := common.ConfigUpdate{}
		err = proto.Unmarshal(actualData.ConfigUpdate, &actualConfigUpdate)
		Expect(err).NotTo(HaveOccurred())

		Expect(actualConfigUpdate).To(Equal(expectedConfigUpdate))
		// SET STUFF TO EQUAL
		actualTimestamp := actualHeader.Timestamp

		expectedHeader.Timestamp = actualTimestamp

		expectedData.ConfigUpdate = actualData.ConfigUpdate

		// REMARSHAL EVERYTHING
		expectedPayload.Data, err = proto.Marshal(&expectedData)
		Expect(err).NotTo(HaveOccurred())

		expectedPayload.Header.ChannelHeader, err = proto.Marshal(&expectedHeader)
		Expect(err).NotTo(HaveOccurred())

		expectedEnvelope.Payload, err = proto.Marshal(&expectedPayload)
		Expect(err).NotTo(HaveOccurred())

		// Expect(envelope).To(Equal(expectedEnvelope))
		Expect(proto.Equal(envelope, &expectedEnvelope)).To(BeTrue())

		// expectedPayload := common.Payload{}
		// err = proto.Unmarshal(expectedEnvelope.Payload, &expectedPayload)
		// Expect(err).NotTo(HaveOccurred())
		//
		// expectedHeader := expectedPayload.Header
		// expectedChannelHeader := common.ChannelHeader{}
		// err = proto.Unmarshal(expectedHeader.ChannelHeader, &expectedChannelHeader)
		// Expect(err).NotTo(HaveOccurred())
		//
		// payload := common.Payload{}
		// err = proto.Unmarshal(envelope.Payload, &payload)
		// Expect(err).NotTo(HaveOccurred())
		//
		// header := payload.Header
		// channelHeader := common.ChannelHeader{}
		// err = proto.Unmarshal(header.ChannelHeader, &channelHeader)
		// Expect(err).NotTo(HaveOccurred())
		//
		// By("checking channel headers are equal")
		// // Set timestamps to match
		// // the headers were generated at different times
		// expectedChannelHeader.Timestamp = channelHeader.Timestamp
		// Expect(proto.Equal(&channelHeader, &expectedChannelHeader)).To(BeTrue())
		//
		// expectedConfigUpdateEnv := common.ConfigUpdateEnvelope{}
		// err = proto.Unmarshal(expectedPayload.Data, &expectedConfigUpdateEnv)
		// Expect(err).ToNot(HaveOccurred())
		// expectedConfigUpdate := common.ConfigUpdate{}
		// err = proto.Unmarshal(expectedConfigUpdateEnv.ConfigUpdate, &expectedConfigUpdate)
		// Expect(err).ToNot(HaveOccurred())
		//
		// configUpdateEnv := common.ConfigUpdateEnvelope{}
		// err = proto.Unmarshal(payload.Data, &configUpdateEnv)
		// Expect(err).ToNot(HaveOccurred())
		// configUpdate := common.ConfigUpdate{}
		// err = proto.Unmarshal(configUpdateEnv.ConfigUpdate, &configUpdate)
		// Expect(err).ToNot(HaveOccurred())
		//
		// By("checking config update are equal")
		// Expect(proto.Equal(&configUpdate, &expectedConfigUpdate)).To(BeTrue())
		//
		// // Stuff
		// expectedEnvelope = common.Envelope{
		// 	ConfigUpdateEnvelope: protoMarshalOrPanic(configUpdate),
		// }
		//
		// By("comparing deep unmarshaled JSON envelopes")
		// var buffer bytes.Buffer
		// err = protolator.DeepMarshalJSON(&buffer, envelope)
		// Expect(err).NotTo(HaveOccurred())
		//
		// var expectedBuffer bytes.Buffer
		// err = protolator.DeepMarshalJSON(&expectedBuffer, &expectedEnvelope)
		// Expect(err).NotTo(HaveOccurred())
		// Expect(buffer).To(Equal(expectedBuffer))
		//
	})
})

func createStandardPolicies() map[string]*config.Policy {
	return map[string]*config.Policy{
		config.ReadersPolicyKey: {
			Type: "ImplicitMeta",
			Rule: "ANY Readers",
		},
		config.WritersPolicyKey: {
			Type: "ImplicitMeta",
			Rule: "ANY Writers",
		},
		config.AdminsPolicyKey: {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Admins",
		},
		config.LifecycleEndorsementPolicyKey: {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Endorsement",
		},
		config.EndorsementPolicyKey: {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Endorsement",
		},
	}
}

func createOrgStandardPolicies() map[string]*config.Policy {
	return map[string]*config.Policy{
		config.ReadersPolicyKey: {
			Type: "ImplicitMeta",
			Rule: "ANY Readers",
		},
		config.WritersPolicyKey: {
			Type: "ImplicitMeta",
			Rule: "ANY Writers",
		},
		config.AdminsPolicyKey: {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Admins",
		},
		config.EndorsementPolicyKey: {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Endorsement",
		},
	}
}
