/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"bytes"
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/common/tools/protolator"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
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

var _ = Describe("does stuff", func() {

	var (
		testDir   string
		network   *nwo.Network
		profile   *Profile
		mspConfig *MSPConfig
	)

	BeforeEach(func() {
		var err error
		testDir, err = ioutil.TempDir("", "config")
		Expect(err).NotTo(HaveOccurred())

		network = nwo.New(nwo.BasicSolo(), testDir, nil, StartPort(), components)

		network.GenerateConfigTree()

		network.Bootstrap()

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
						MSPDir:   network.PeerOrgMSPDir(network.Organization("Org1")),
					},
					&Organization{
						Name:     "Org2",
						ID:       "Org2MSP",
						Policies: CreateOrgStandardPolicies(),
						MSPType:  "bccsp",
						MSPDir:   network.PeerOrgMSPDir(network.Organization("Org2")),
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
		if network != nil {
			network.Cleanup()
		}
		os.RemoveAll(testDir)
	})

	It("creates envelope", func() {

		createChannelTxPath := network.CreateChannelTxPath(profile.ChannelID)

		envelope, err := CreateChannelTx(profile, mspConfig)
		Expect(err).ToNot(HaveOccurred())
		Expect(envelope).ToNot(BeNil())

		By("Use configtxgen: channel creation configtx")
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

		By("Compare deep unmarshaled JSON envelopes")
		var buffer bytes.Buffer
		err = protolator.DeepUnmarshalJSON(&buffer, envelope)
		var expectedBuffer bytes.Buffer
		err = protolator.DeepUnmarshalJSON(&expectedBuffer, &expectedEnvelope)
		Expect(buffer).To(Equal(expectedBuffer))

		expectedPayload := common.Payload{}
		err = proto.Unmarshal(expectedEnvelope.Payload, &expectedPayload)

		expectedHeader := expectedPayload.Header
		expectedChannelHeader := common.ChannelHeader{}
		err = proto.Unmarshal(expectedHeader.ChannelHeader, &expectedChannelHeader)

		payload := common.Payload{}
		err = proto.Unmarshal(envelope.Payload, &payload)

		header := payload.Header
		channelHeader := common.ChannelHeader{}
		err = proto.Unmarshal(header.ChannelHeader, &channelHeader)

		By("check channel headers are equal")
		// Set timestamps to match
		// the headers were generated at different times
		expectedChannelHeader.Timestamp = channelHeader.Timestamp
		Expect(proto.Equal(&channelHeader, &expectedChannelHeader)).To(BeTrue())

		expectedConfigUpdateEnv := common.ConfigUpdateEnvelope{}
		err = proto.Unmarshal(expectedPayload.Data, &expectedConfigUpdateEnv)
		Expect(err).ToNot(HaveOccurred())
		expectedConfigUpdate := common.ConfigUpdate{}
		err = proto.Unmarshal(expectedConfigUpdateEnv.ConfigUpdate, &expectedConfigUpdate)
		Expect(err).ToNot(HaveOccurred())

		configUpdateEnv := common.ConfigUpdateEnvelope{}
		err = proto.Unmarshal(payload.Data, &configUpdateEnv)
		Expect(err).ToNot(HaveOccurred())
		configUpdate := common.ConfigUpdate{}
		err = proto.Unmarshal(configUpdateEnv.ConfigUpdate, &configUpdate)
		Expect(err).ToNot(HaveOccurred())

		By("check config update are equal")
		Expect(proto.Equal(&configUpdate, &expectedConfigUpdate)).To(BeTrue())

	})

})
