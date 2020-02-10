/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import "math"

const (
	msgVersion = int32(0)

	// These values are fixed for the genesis block.
	epoch = 0

	// ImplicitMetaPolicyType is the 'Type' string for implicit meta policies
	ImplicitMetaPolicyType = "ImplicitMeta"

	defaultHashingAlgorithm = "SHA256"

	defaultBlockDataHashingStructureWidth = math.MaxUint32

	// ConsortiumKey is the key for the common.ConfigValue for the Consortium message
	ConsortiumKey = "Consortium"

	// HashingAlgorithmKey is the common.ConfigItem type key name for the HashingAlgorithm message
	HashingAlgorithmKey = "HashingAlgorithm"

	// BlockDataHashingStructureKey is the common.ConfigItem type key name for the BlockDataHashingStructure message
	BlockDataHashingStructureKey = "BlockDataHashingStructure"

	// OrdererAddressesKey is the common.ConfigItem type key name for the OrdererAddresses message
	OrdererAddressesKey = "OrdererAddresses"

	// ChannelGroupKey is the name of the channel group
	ChannelGroupKey = "Channel"

	// CapabilitiesKey is the name of the key which refers to capabilities, it appears at the channel,
	// application, and orderer levels and this constant is used for all three.
	CapabilitiesKey = "Capabilities"

	ordererAdminsPolicyName = "/Channel/Orderer/Admins"

	// EndpointsKey is the common.ConfigValue key name for the Endpoints message in the OrdererOrgGroup.
	EndpointsKey = "Endpoints"

	// MSPKey is the key for the MSP definition in orderer groups
	MSPKey = "MSP"

	// BlockValidationPolicyKey TODO
	BlockValidationPolicyKey = "BlockValidation"

	// BatchSizeKey is the common.ConfigItem type key name for the BatchSize message.
	BatchSizeKey = "BatchSize"

	// BatchTimeoutKey is the common.ConfigItem type key name for the BatchTimeout message.
	BatchTimeoutKey = "BatchTimeout"

	AdminsPolicyKey = "Admins"

	// ReadersPolicyKey is the key used for the read policy
	ReadersPolicyKey = "Readers"

	// WritersPolicyKey is the key used for the read policy
	WritersPolicyKey = "Writers"

	// ChannelRestrictionsKey is the key name for the ChannelRestrictions message.
	ChannelRestrictionsKey = "ChannelRestrictions"

	// ConsensusTypeSolo identifies the solo consensus implementation.
	ConsensusTypeSolo = "solo"

	// ConsensusTypeKafka identifies the Kafka-based consensus implementation.
	ConsensusTypeKafka = "kafka"

	// ConsortiumsGroupKey is the group name for the consortiums config
	ConsortiumsGroupKey = "Consortiums"

	// ConsensusTypeKafka identifies the Kafka-based consensus implementation.
	ConsensusTypeEtcdRaft = "etcdraft"

	// KafkaBrokersKey is the common.ConfigItem type key name for the KafkaBrokers message.
	KafkaBrokersKey = "KafkaBrokers"

	// ConsensusTypeKey is the common.ConfigItem type key name for the ConsensusType message.
	ConsensusTypeKey = "ConsensusType"

	// OrdererGroupKey is the group name for the orderer config.
	OrdererGroupKey = "Orderer"

	// ApplicationGroupKey is the group name for the Application config
	ApplicationGroupKey = "Application"

	// ACLsKey is the name of the ACLs config
	ACLsKey = "ACLs"

	// AnchorPeersKey is the key name for the AnchorPeers ConfigValue
	AnchorPeersKey = "AnchorPeers"

	// ChannelCreationPolicyKey is the key used in the consortium config to denote the policy
	// to be used in evaluating whether a channel creation request is authorized
	ChannelCreationPolicyKey = "ChannelCreationPolicy"

	// SignaturePolicyType is the 'Type' string for signature policies
	SignaturePolicyType = "Signature"
)
