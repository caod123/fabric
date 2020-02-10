/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
)

// Orderer contains configuration associated to a channel.
type Orderer struct {
	OrdererType   string
	Addresses     []string
	BatchTimeout  time.Duration
	BatchSize     BatchSize
	Kafka         Kafka
	EtcdRaft      *etcdraft.ConfigMetadata
	Organizations []*Organization
	MaxChannels   uint64
	Capabilities  map[string]bool
	Policies      map[string]*Policy
}

// Orderer Group

// NewOrdererGroup returns the orderer component of the channel configuration.  It defines parameters of the ordering service
// about how large blocks should be, how frequently they should be emitted, etc. as well as the organizations of the ordering network.
// It sets the mod_policy of all elements to "Admins".  This group is always present in any channel configuration.
func NewOrdererGroup(conf *Orderer, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	ordererGroup := NewConfigGroup()
	if err := AddPolicies(ordererGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies to orderer group: %v", err)
	}
	ordererGroup.Policies[BlockValidationPolicyKey] = &common.ConfigPolicy{
		Policy:    ImplicitMetaAnyPolicy(WritersPolicyKey).Value(),
		ModPolicy: AdminsPolicyKey,
	}
	addValue(ordererGroup, BatchSizeValue(
		conf.BatchSize.MaxMessageCount,
		conf.BatchSize.AbsoluteMaxBytes,
		conf.BatchSize.PreferredMaxBytes,
	), AdminsPolicyKey)
	addValue(ordererGroup, BatchTimeoutValue(conf.BatchTimeout.String()), AdminsPolicyKey)
	addValue(ordererGroup, ChannelRestrictionsValue(conf.MaxChannels), AdminsPolicyKey)

	if len(conf.Capabilities) > 0 {
		addValue(ordererGroup, CapabilitiesValue(conf.Capabilities), AdminsPolicyKey)
	}

	var consensusMetadata []byte
	var err error

	switch conf.OrdererType {
	case ConsensusTypeSolo:
	case ConsensusTypeKafka:
		addValue(ordererGroup, KafkaBrokersValue(conf.Kafka.Brokers), AdminsPolicyKey)
	case ConsensusTypeEtcdRaft:
		if consensusMetadata, err = MarshalEtcdRaftMetadata(conf.EtcdRaft); err != nil {
			return nil, fmt.Errorf("cannot marshal metadata for orderer type %s: %v", ConsensusTypeEtcdRaft, err)
		}
	default:
		return nil, fmt.Errorf("unknown orderer type: %s error: %v", conf.OrdererType, err)
	}

	addValue(ordererGroup, ConsensusTypeValue(conf.OrdererType, consensusMetadata), AdminsPolicyKey)

	for _, org := range conf.Organizations {
		var err error
		ordererGroup.Groups[org.Name], err = NewOrdererOrgGroup(org, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create orderer org %v", err)
		}
	}

	ordererGroup.ModPolicy = AdminsPolicyKey
	return ordererGroup, nil
}

// NewOrdererOrgGroup returns an orderer org component of the channel configuration.  It defines the crypto material for the
// organization (its MSP).  It sets the mod_policy of all elements to "Admins".
func NewOrdererOrgGroup(conf *Organization, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	ordererOrgGroup := NewConfigGroup()
	ordererOrgGroup.ModPolicy = AdminsPolicyKey

	if conf.SkipAsForeign {
		return ordererOrgGroup, nil
	}

	if err := AddPolicies(ordererOrgGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies to orderer org group '%s' error: %v", conf.Name, err)
	}

	addValue(ordererOrgGroup, MSPValue(mspConfig), AdminsPolicyKey)

	if len(conf.OrdererEndpoints) > 0 {
		addValue(ordererOrgGroup, EndpointsValue(conf.OrdererEndpoints), AdminsPolicyKey)
	}

	return ordererOrgGroup, nil
}

// BatchSizeValue returns the config definition for the orderer batch size.
// It is a value for the /Channel/Orderer group.
func BatchSizeValue(maxMessages, absoluteMaxBytes, preferredMaxBytes uint32) *StandardConfigValue {
	return &StandardConfigValue{
		key: BatchSizeKey,
		value: &orderer.BatchSize{
			MaxMessageCount:   maxMessages,
			AbsoluteMaxBytes:  absoluteMaxBytes,
			PreferredMaxBytes: preferredMaxBytes,
		},
	}
}

// BatchTimeoutValue returns the config definition for the orderer batch timeout.
// It is a value for the /Channel/Orderer group.
func BatchTimeoutValue(timeout string) *StandardConfigValue {
	return &StandardConfigValue{
		key: BatchTimeoutKey,
		value: &orderer.BatchTimeout{
			Timeout: timeout,
		},
	}
}

// EndpointsValue returns the config definition for the orderer addresses at an org scoped level.
// It is a value for the /Channel/Orderer/<OrgName> group.
func EndpointsValue(addresses []string) *StandardConfigValue {
	return &StandardConfigValue{
		key: EndpointsKey,
		value: &common.OrdererAddresses{
			Addresses: addresses,
		},
	}
}

// ChannelRestrictionsValue returns the config definition for the orderer channel restrictions.
// It is a value for the /Channel/Orderer group.
func ChannelRestrictionsValue(maxChannelCount uint64) *StandardConfigValue {
	return &StandardConfigValue{
		key: ChannelRestrictionsKey,
		value: &orderer.ChannelRestrictions{
			MaxCount: maxChannelCount,
		},
	}
}

// KafkaBrokersValue returns the config definition for the addresses of the ordering service's Kafka brokers.
// It is a value for the /Channel/Orderer group.
func KafkaBrokersValue(brokers []string) *StandardConfigValue {
	return &StandardConfigValue{
		key: KafkaBrokersKey,
		value: &orderer.KafkaBrokers{
			Brokers: brokers,
		},
	}
}

// MarshalEtcdRaftMetadata serializes etcd RAFT metadata.
func MarshalEtcdRaftMetadata(md *etcdraft.ConfigMetadata) ([]byte, error) {
	copyMd := proto.Clone(md).(*etcdraft.ConfigMetadata)
	for _, c := range copyMd.Consenters {
		// Expect the user to set the config value for client/server certs to the
		// path where they are persisted locally, then load these files to memory.
		clientCert, err := ioutil.ReadFile(string(c.GetClientTlsCert()))
		if err != nil {
			return nil, fmt.Errorf("cannot load client cert for consenter %s:%d: %s", c.GetHost(), c.GetPort(), err)
		}
		c.ClientTlsCert = clientCert

		serverCert, err := ioutil.ReadFile(string(c.GetServerTlsCert()))
		if err != nil {
			return nil, fmt.Errorf("cannot load server cert for consenter %s:%d: %s", c.GetHost(), c.GetPort(), err)
		}
		c.ServerTlsCert = serverCert
	}
	return proto.Marshal(copyMd)
}

// ConsensusTypeValue returns the config definition for the orderer consensus type.
// It is a value for the /Channel/Orderer group.
func ConsensusTypeValue(consensusType string, consensusMetadata []byte) *StandardConfigValue {
	return &StandardConfigValue{
		key: ConsensusTypeKey,
		value: &orderer.ConsensusType{
			Type:     consensusType,
			Metadata: consensusMetadata,
		},
	}
}
