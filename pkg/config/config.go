/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-protos-go/msp"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"

	"github.com/hyperledger/fabric-protos-go/common"
)

// MSPConfig encapsulates configuration information for an MSP
type MSPConfig struct {
	Admincert                     [][]byte                 // pem encoded admin cert
	Rootcert                      [][]byte                 // pem encoded root cert (CA)
	IntermediateCert              [][]byte                 // pem encoded intermediates cert
	SigningIdentity               *msp.SigningIdentityInfo // not sure what is this
	Name                          string                   // ID, not sure which ID
	OrganizationalUnitIdentifiers *msp.FabricOUIdentifier  // something to do with NodeOU?
	RevocationList                [][]byte                 // pem encoded crls. what is crls?
	CryptoConfig                  *msp.FabricCryptoConfig  // bsscp stuff. might need struct for this
	TLSRootCerts                  [][]byte                 //pem encoded tls ca cert
	TLSIntermediateCerts          [][]byte                 //pem encoded tls intermediate certs
	FabricNodeOus                 *msp.FabricNodeOUs       // nodeOU stuff.
}

// Profile encapsulates basic information for a configtxgen profile.
type Profile struct {
	Consortium   string
	Application  *Application
	Orderer      *Orderer
	Consortiums  map[string]*Consortium
	Capabilities map[string]bool
	Policies     map[string]*Policy
	ChannelID    string
}

// Policy encodes a channel config policy
type Policy struct {
	Type string
	Rule string
}

// Resources encodes the application-level resources configuration needed to
// seed the resource tree
type Resources struct {
	DefaultModPolicy string
}

// Organization encodes the organization-level configuration needed in
// config transactions.
type Organization struct {
	Name     string
	ID       string
	MSPDir   string
	MSPType  string
	Policies map[string]*Policy

	// Note: Viper deserialization does not seem to care for
	// embedding of types, so we use one organization struct
	// for both orderers and applications.
	AnchorPeers      []*AnchorPeer
	OrdererEndpoints []string

	// AdminPrincipal is deprecated and may be removed in a future release
	// it was used for modifying the default policy generation, but policies
	// may now be specified explicitly so it is redundant and unnecessary
	AdminPrincipal string

	// SkipAsForeign indicates that this org definition is actually unknown to this
	// instance of the tool, so, parsing of this org's parameters should be ignored.
	SkipAsForeign bool
}

type BatchSize struct {
	MaxMessageCount   uint32
	AbsoluteMaxBytes  uint32
	PreferredMaxBytes uint32
}

// Kafka contains configuration for the Kafka-based orderer.
type Kafka struct {
	Brokers []string
}

type Option func(options)

// Options for extensibility
type options struct{}

// StandardConfigPolicy ...
type StandardConfigPolicy struct {
	key   string
	value *common.Policy
}

// Key is the key this value should be stored in the *common.ConfigGroup.Values map.
func (scv *StandardConfigPolicy) Key() string {
	return scv.key
}

// Value is the *common.Policy which should be stored as the *common.ConfigPolicy.Policy.
func (scv *StandardConfigPolicy) Value() *common.Policy {
	return scv.value
}

// marshalOrPanic serializes a protobuf message and panics if this
// operation fails
func marshalOrPanic(pb proto.Message) []byte {
	data, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}
	return data
}

// MakeChannelHeader creates a ChannelHeader.
func makeChannelHeader(headerType common.HeaderType, version int32, channelID string, epoch uint64) *common.ChannelHeader {
	return &common.ChannelHeader{
		Type:    int32(headerType),
		Version: version,
		Timestamp: &timestamp.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos:   0,
		},
		ChannelId: channelID,
		Epoch:     epoch,
	}
}

// MakePayloadHeader creates a Payload Header.
func makePayloadHeader(ch *common.ChannelHeader, sh *common.SignatureHeader) *common.Header {
	return &common.Header{
		ChannelHeader:   marshalOrPanic(ch),
		SignatureHeader: marshalOrPanic(sh),
	}
}

// newConfigGroup ...
func newConfigGroup() *common.ConfigGroup {
	return &common.ConfigGroup{
		Groups:   make(map[string]*common.ConfigGroup),
		Values:   make(map[string]*common.ConfigValue),
		Policies: make(map[string]*common.ConfigPolicy),
	}
}

// StandardConfigValue implements the ConfigValue interface.
type StandardConfigValue struct {
	key   string
	value proto.Message
}

// Key is the key this value should be stored in the *common.ConfigGroup.Values map.
func (scv *StandardConfigValue) Key() string {
	return scv.key
}

// Value is the message which should be marshaled to opaque bytes for the *common.ConfigValue.value.
func (scv *StandardConfigValue) Value() proto.Message {
	return scv.value
}

// newChannelGroup defines the root of the channel configuration
func newChannelGroup(conf *Profile, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	channelGroup := newConfigGroup()
	if err := addPolicies(channelGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies to channel group: %v", err)
	}

	addValue(channelGroup, hashingAlgorithmValue(), AdminsPolicyKey)
	addValue(channelGroup, blockDataHashingStructureValue(), AdminsPolicyKey)
	if conf.Orderer != nil && len(conf.Orderer.Addresses) > 0 {
		addValue(channelGroup, ordererAddressesValue(conf.Orderer.Addresses), ordererAdminsPolicyName)
	}

	if conf.Consortium != "" {
		addValue(channelGroup, consortiumValue(conf.Consortium), AdminsPolicyKey)
	}

	if len(conf.Capabilities) > 0 {
		addValue(channelGroup, capabilitiesValue(conf.Capabilities), AdminsPolicyKey)
	}

	var err error
	if conf.Orderer != nil {
		channelGroup.Groups[OrdererGroupKey], err = NewOrdererGroup(conf.Orderer, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create orderer group: %v", err)
		}
	}

	if conf.Application != nil {
		channelGroup.Groups[ApplicationGroupKey], err = NewApplicationGroup(conf.Application, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create application group: %v", err)
		}
	}

	if conf.Consortiums != nil {
		channelGroup.Groups[ConsortiumsGroupKey], err = NewConsortiumsGroup(conf.Consortiums, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create consortiums group: %v", err)
		}
	}

	channelGroup.ModPolicy = AdminsPolicyKey
	return channelGroup, nil
}

// Hashing

// HashingAlgorithmValue returns the only currently valid hashing algorithm.
// It is a value for the /Channel group.
func hashingAlgorithmValue() *StandardConfigValue {
	return &StandardConfigValue{
		key: HashingAlgorithmKey,
		value: &common.HashingAlgorithm{
			Name: defaultHashingAlgorithm,
		},
	}
}

// BlockDataHashingStructureValue returns the only currently valid block data hashing structure.
// It is a value for the /Channel group.
func blockDataHashingStructureValue() *StandardConfigValue {
	return &StandardConfigValue{
		key: BlockDataHashingStructureKey,
		value: &common.BlockDataHashingStructure{
			Width: defaultBlockDataHashingStructureWidth,
		},
	}
}

func addValue(cg *common.ConfigGroup, value *StandardConfigValue, modPolicy string) {
	cg.Values[value.Key()] = &common.ConfigValue{
		Value:     marshalOrPanic(value.Value()),
		ModPolicy: modPolicy,
	}
}

// AddPolicies ...
func addPolicies(cg *common.ConfigGroup, policyMap map[string]*Policy, modPolicy string) error {
	switch {
	case policyMap == nil:
		return errors.New("no policies defined")
	case policyMap[AdminsPolicyKey] == nil:
		return errors.New("no Admins policy defined")
	case policyMap[ReadersPolicyKey] == nil:
		return errors.New("no Readers policy defined")
	case policyMap[WritersPolicyKey] == nil:
		return errors.New("no Writers policy defined")
	}

	for policyName, policy := range policyMap {
		switch policy.Type {
		case ImplicitMetaPolicyType:
			imp, err := implicitMetaFromString(policy.Rule)
			if err != nil {
				return fmt.Errorf("invalid implicit meta policy rule: '%s' error: %v", policy.Rule, err)
			}
			cg.Policies[policyName] = &common.ConfigPolicy{
				ModPolicy: modPolicy,
				Policy: &common.Policy{
					Type:  int32(common.Policy_IMPLICIT_META),
					Value: marshalOrPanic(imp),
				},
			}
		case SignaturePolicyType:
			sp, err := FromString(policy.Rule)
			if err != nil {
				return fmt.Errorf("invalid signature policy rule '%s' error: %v", policy.Rule, err)
			}
			cg.Policies[policyName] = &common.ConfigPolicy{
				ModPolicy: modPolicy,
				Policy: &common.Policy{
					Type:  int32(common.Policy_SIGNATURE),
					Value: marshalOrPanic(sp),
				},
			}
		default:
			return fmt.Errorf("unknown policy type: %s", policy.Type)
		}
	}
	return nil
}

// ImplicitMetaFromString ...
func implicitMetaFromString(input string) (*common.ImplicitMetaPolicy, error) {
	args := strings.Split(input, " ")
	if len(args) != 2 {
		return nil, fmt.Errorf("expected two space separated tokens, but got %d", len(args))
	}

	res := &common.ImplicitMetaPolicy{
		SubPolicy: args[1],
	}

	switch args[0] {
	case common.ImplicitMetaPolicy_ANY.String():
		res.Rule = common.ImplicitMetaPolicy_ANY
	case common.ImplicitMetaPolicy_ALL.String():
		res.Rule = common.ImplicitMetaPolicy_ALL
	case common.ImplicitMetaPolicy_MAJORITY.String():
		res.Rule = common.ImplicitMetaPolicy_MAJORITY
	default:
		return nil, fmt.Errorf("unknown rule type '%s', expected ALL, ANY, or MAJORITY", args[0])
	}

	return res, nil
}

// OrdererAddressesValue returns the a config definition for the orderer addresses.
// It is a value for the /Channel group.
func ordererAddressesValue(addresses []string) *StandardConfigValue {
	return &StandardConfigValue{
		key: OrdererAddressesKey,
		value: &common.OrdererAddresses{
			Addresses: addresses,
		},
	}
}

// capabilitiesValue returns the config definition for a a set of capabilities.
// It is a value for the /Channel/Orderer, Channel/Application/, and /Channel groups.
func capabilitiesValue(capabilities map[string]bool) *StandardConfigValue {
	c := &common.Capabilities{
		Capabilities: make(map[string]*common.Capability),
	}

	for capability, required := range capabilities {
		if !required {
			continue
		}
		c.Capabilities[capability] = &common.Capability{}
	}

	return &StandardConfigValue{
		key:   CapabilitiesKey,
		value: c,
	}
}

// MSPValue returns the config definition for an MSP.
// It is a value for the /Channel/Orderer/*, /Channel/Application/*, and /Channel/Consortiums/*/*/* groups.
func MSPValue(mspDef *msp.MSPConfig) *StandardConfigValue {
	return &StandardConfigValue{
		key:   MSPKey,
		value: mspDef,
	}
}

func makeImplicitMetaPolicy(subPolicyName string, rule common.ImplicitMetaPolicy_Rule) *common.Policy {
	return &common.Policy{
		Type: int32(common.Policy_IMPLICIT_META),
		Value: marshalOrPanic(&common.ImplicitMetaPolicy{
			Rule:      rule,
			SubPolicy: subPolicyName,
		}),
	}
}

// ImplicitMetaAnyPolicy defines an implicit meta policy whose sub_policy and key is policyname with rule ANY.
func implicitMetaAnyPolicy(policyName string) *StandardConfigPolicy {
	return &StandardConfigPolicy{
		key:   policyName,
		value: makeImplicitMetaPolicy(policyName, common.ImplicitMetaPolicy_ANY),
	}
}

// DefaultConfigTemplate generates a config template based on the assumption that
// the input profile is a channel creation template and no system channel context
// is available.
func defaultConfigTemplate(conf *Profile, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	channelGroup, err := newChannelGroup(conf, mspConfig)
	if err != nil {
		return nil, err
	}

	if _, ok := channelGroup.Groups[ApplicationGroupKey]; !ok {
		return nil, errors.New("channel template config must contain an application section")
	}

	channelGroup.Groups[ApplicationGroupKey].Values = nil
	channelGroup.Groups[ApplicationGroupKey].Policies = nil

	return channelGroup, nil
}

// NewChannelCreateConfigUpdate generates a ConfigUpdate which can be sent to the orderer to create a new channel.  Optionally, the channel group of the
// ordering system channel may be passed in, and the resulting ConfigUpdate will extract the appropriate versions from this file.
func newChannelCreateConfigUpdate(channelID string, conf *Profile, templateConfig *common.ConfigGroup, mspConfig *msp.MSPConfig) (*common.ConfigUpdate, error) {
	if conf.Application == nil {
		return nil, errors.New("cannot define a new channel with no Application section")
	}

	if conf.Consortium == "" {
		return nil, errors.New("cannot define a new channel with no Consortium value")
	}

	newChannelGroup, err := newChannelGroup(conf, mspConfig)
	if err != nil {
		return nil, fmt.Errorf("could not turn parse profile into channel group %v", err)
	}

	updt, err := Compute(&common.Config{ChannelGroup: templateConfig}, &common.Config{ChannelGroup: newChannelGroup})
	if err != nil {
		return nil, fmt.Errorf("could not compute update %v", err)
	}

	// Add the consortium name to create the channel for into the write set as required.
	updt.ChannelId = channelID
	updt.ReadSet.Values[ConsortiumKey] = &common.ConfigValue{Version: 0}
	updt.WriteSet.Values[ConsortiumKey] = &common.ConfigValue{
		Version: 0,
		Value: marshalOrPanic(&common.Consortium{
			Name: conf.Consortium,
		}),
	}

	return updt, nil
}

// CreateEnvelope creates an unsigned envelope of type txType using with the marshalled
// proto message
func createEnvelope(
	txType common.HeaderType,
	channelID string,
	dataMsg proto.Message,
	msgVersion int32,
	epoch uint64,
) (*common.Envelope, error) {

	payloadChannelHeader := makeChannelHeader(txType, msgVersion, channelID, epoch)
	payloadSignatureHeader := &common.SignatureHeader{}

	data, err := proto.Marshal(dataMsg)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling %v", err)
	}

	paylBytes := marshalOrPanic(
		&common.Payload{
			Header: makePayloadHeader(payloadChannelHeader, payloadSignatureHeader),
			Data:   data,
		},
	)

	env := &common.Envelope{
		Payload: paylBytes,
	}

	return env, nil
}

// CreateChannelTx creates a channel using the provided config with no base profile
func CreateChannelTx(profile *Profile, mspConfig *MSPConfig, options ...Option) (*common.Envelope, error) {

	if profile == nil {
		return nil, errors.New("failed to create channel tx because profile is empty")
	}

	channelID := profile.ChannelID

	if channelID == "" {
		return nil, errors.New("failed to create channel tx because channel ID is empty")
	}

	fmspconf := &msp.FabricMSPConfig{
		Admins:                        mspConfig.Admincert,
		RootCerts:                     mspConfig.Rootcert,
		IntermediateCerts:             mspConfig.IntermediateCert,
		SigningIdentity:               mspConfig.SigningIdentity,
		Name:                          mspConfig.Name,
		OrganizationalUnitIdentifiers: []*msp.FabricOUIdentifier{mspConfig.OrganizationalUnitIdentifiers},
		RevocationList:                mspConfig.RevocationList,
		CryptoConfig:                  mspConfig.CryptoConfig,
		TlsRootCerts:                  mspConfig.TLSRootCerts,
		TlsIntermediateCerts:          mspConfig.TLSIntermediateCerts,
		FabricNodeOus:                 mspConfig.FabricNodeOus,
	}

	fmpsjs, _ := proto.Marshal(fmspconf)
	mspconf := &msp.MSPConfig{Config: fmpsjs, Type: 0} //Type 0 : FABRIC

	ct, err := defaultConfigTemplate(profile, mspconf)
	if err != nil {
		return nil, fmt.Errorf("could not generate default config template: %v", err)
	}

	newChannelConfigUpdate, err := newChannelCreateConfigUpdate(channelID, profile, ct, mspconf)
	if err != nil {
		return nil, fmt.Errorf("failed to generated config update: %v", err)
	}

	newConfigUpdateEnv := &common.ConfigUpdateEnvelope{
		ConfigUpdate: marshalOrPanic(newChannelConfigUpdate),
	}

	env, err := createEnvelope(common.HeaderType_CONFIG_UPDATE, channelID, newConfigUpdateEnv, msgVersion, epoch)

	return env, err

}
