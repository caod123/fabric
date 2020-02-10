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

// MSPConfig ...
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

// Profile ...
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

// ConfigPolicy ...
type ConfigPolicy interface {
	// Key is the key this value should be stored in the *common.ConfigGroup.Policies map.
	Key() string

	// Value is the backing policy implementation for this ConfigPolicy
	Value() *common.Policy
}

// MarshalOrPanic serializes a protobuf message and panics if this
// operation fails
func MarshalOrPanic(pb proto.Message) []byte {
	data, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}
	return data
}

// Marshal serializes a protobuf message.
func Marshal(pb proto.Message) ([]byte, error) {
	return proto.Marshal(pb)
}

// MakeChannelHeader creates a ChannelHeader.
func MakeChannelHeader(headerType common.HeaderType, version int32, channelID string, epoch uint64) *common.ChannelHeader {
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

// MakeSignatureHeader creates a SignatureHeader.
func MakeSignatureHeader(serializedCreatorCertChain []byte, nonce []byte) *common.SignatureHeader {
	return &common.SignatureHeader{
		Creator: serializedCreatorCertChain,
		Nonce:   nonce,
	}
}

// MakePayloadHeader creates a Payload Header.
func MakePayloadHeader(ch *common.ChannelHeader, sh *common.SignatureHeader) *common.Header {
	return &common.Header{
		ChannelHeader:   MarshalOrPanic(ch),
		SignatureHeader: MarshalOrPanic(sh),
	}
}

// NewConfigGroup ...
func NewConfigGroup() *common.ConfigGroup {
	return &common.ConfigGroup{
		Groups:   make(map[string]*common.ConfigGroup),
		Values:   make(map[string]*common.ConfigValue),
		Policies: make(map[string]*common.ConfigPolicy),
	}
}

type ConfigValue interface {
	// Key is the key this value should be stored in the *common.ConfigGroup.Values map.
	Key() string

	// Value is the message which should be marshaled to opaque bytes for the *common.ConfigValue.value.
	Value() proto.Message
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

// NewChannelGroup ...
func NewChannelGroup(conf *Profile, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	channelGroup := NewConfigGroup()
	if err := AddPolicies(channelGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies to channel group: %v", err)
	}

	addValue(channelGroup, HashingAlgorithmValue(), AdminsPolicyKey)
	addValue(channelGroup, BlockDataHashingStructureValue(), AdminsPolicyKey)
	if conf.Orderer != nil && len(conf.Orderer.Addresses) > 0 {
		addValue(channelGroup, OrdererAddressesValue(conf.Orderer.Addresses), ordererAdminsPolicyName)
	}

	if conf.Consortium != "" {
		addValue(channelGroup, ConsortiumValue(conf.Consortium), AdminsPolicyKey)
	}

	if len(conf.Capabilities) > 0 {
		addValue(channelGroup, CapabilitiesValue(conf.Capabilities), AdminsPolicyKey)
	}

	var err error
	if conf.Orderer != nil {
		channelGroup.Groups[OrdererGroupKey], err = NewOrdererGroup(conf.Orderer, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create orderer group. %v", err)
		}
	}

	if conf.Application != nil {
		channelGroup.Groups[ApplicationGroupKey], err = NewApplicationGroup(conf.Application, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create application group. %v", err)
		}
	}

	if conf.Consortiums != nil {
		channelGroup.Groups[ConsortiumsGroupKey], err = NewConsortiumsGroup(conf.Consortiums, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create consortiums group %v", err)
		}
	}

	channelGroup.ModPolicy = AdminsPolicyKey
	return channelGroup, nil
}

// Hashing

// HashingAlgorithmValue returns the only currently valid hashing algorithm.
// It is a value for the /Channel group.
func HashingAlgorithmValue() *StandardConfigValue {
	return &StandardConfigValue{
		key: HashingAlgorithmKey,
		value: &common.HashingAlgorithm{
			Name: defaultHashingAlgorithm,
		},
	}
}

// BlockDataHashingStructureValue returns the only currently valid block data hashing structure.
// It is a value for the /Channel group.
func BlockDataHashingStructureValue() *StandardConfigValue {
	return &StandardConfigValue{
		key: BlockDataHashingStructureKey,
		value: &common.BlockDataHashingStructure{
			Width: defaultBlockDataHashingStructureWidth,
		},
	}
}

func addValue(cg *common.ConfigGroup, value *StandardConfigValue, modPolicy string) {
	cg.Values[value.Key()] = &common.ConfigValue{
		Value:     MarshalOrPanic(value.Value()),
		ModPolicy: modPolicy,
	}
}

// AddPolicies ...
func AddPolicies(cg *common.ConfigGroup, policyMap map[string]*Policy, modPolicy string) error {
	switch {
	case policyMap == nil:
		return fmt.Errorf("no policies defined")
	case policyMap[AdminsPolicyKey] == nil:
		return fmt.Errorf("no Admins policy defined")
	case policyMap[ReadersPolicyKey] == nil:
		return fmt.Errorf("no Readers policy defined")
	case policyMap[WritersPolicyKey] == nil:
		return fmt.Errorf("no Writers policy defined")
	}

	for policyName, policy := range policyMap {
		switch policy.Type {
		case ImplicitMetaPolicyType:
			imp, err := ImplicitMetaFromString(policy.Rule)
			if err != nil {
				return fmt.Errorf("invalid implicit meta policy rule: '%s' error: %v", policy.Rule, err)
			}
			cg.Policies[policyName] = &common.ConfigPolicy{
				ModPolicy: modPolicy,
				Policy: &common.Policy{
					Type:  int32(common.Policy_IMPLICIT_META),
					Value: MarshalOrPanic(imp),
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
					Value: MarshalOrPanic(sp),
				},
			}
		default:
			return fmt.Errorf("unknown policy type: %s", policy.Type)
		}
	}
	return nil
}

// ImplicitMetaFromString ...
func ImplicitMetaFromString(input string) (*common.ImplicitMetaPolicy, error) {
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
func OrdererAddressesValue(addresses []string) *StandardConfigValue {
	return &StandardConfigValue{
		key: OrdererAddressesKey,
		value: &common.OrdererAddresses{
			Addresses: addresses,
		},
	}
}

// CapabilitiesValue returns the config definition for a a set of capabilities.
// It is a value for the /Channel/Orderer, Channel/Application/, and /Channel groups.
func CapabilitiesValue(capabilities map[string]bool) *StandardConfigValue {
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
		Value: MarshalOrPanic(&common.ImplicitMetaPolicy{
			Rule:      rule,
			SubPolicy: subPolicyName,
		}),
	}
}

func addPolicy(cg *common.ConfigGroup, policy ConfigPolicy, modPolicy string) {
	cg.Policies[policy.Key()] = &common.ConfigPolicy{
		Policy:    policy.Value(),
		ModPolicy: modPolicy,
	}
}

// SignaturePolicy defines a policy with key policyName and the given signature policy.
func SignaturePolicy(policyName string, sigPolicy *common.SignaturePolicyEnvelope) *StandardConfigPolicy {
	return &StandardConfigPolicy{
		key: policyName,
		value: &common.Policy{
			Type:  int32(common.Policy_SIGNATURE),
			Value: MarshalOrPanic(sigPolicy),
		},
	}
}

// ConfigTemplateFromGroup ...
func ConfigTemplateFromGroup(conf *Profile, cg *common.ConfigGroup) (*common.ConfigGroup, error) {

	template := proto.Clone(cg).(*common.ConfigGroup)
	if template.Groups == nil {
		return nil, errors.New("supplied system channel group has no sub-groups")
	}

	template.Groups[ApplicationGroupKey] = &common.ConfigGroup{
		Groups: map[string]*common.ConfigGroup{},
		Policies: map[string]*common.ConfigPolicy{
			AdminsPolicyKey: {},
		},
	}

	consortiums, ok := template.Groups[ConsortiumsGroupKey]
	if !ok {
		return nil, errors.New("supplied system channel group does not appear to be system channel (missing consortiums group)")
	}

	if consortiums.Groups == nil {
		return nil, errors.New("system channel consortiums group appears to have no consortiums defined")
	}

	consortium, ok := consortiums.Groups[conf.Consortium]
	if !ok {
		return nil, fmt.Errorf("supplied system channel group is missing '%s' consortium", conf.Consortium)
	}

	if conf.Application == nil {
		return nil, errors.New("supplied channel creation profile does not contain an application section")
	}

	for _, organization := range conf.Application.Organizations {
		var ok bool
		template.Groups[ApplicationGroupKey].Groups[organization.Name], ok = consortium.Groups[organization.Name]
		if !ok {
			return nil, fmt.Errorf("consortium %s does not contain member org %s", conf.Consortium, organization.Name)
		}
	}
	delete(template.Groups, ConsortiumsGroupKey)

	addValue(template, ConsortiumValue(conf.Consortium), AdminsPolicyKey)

	return template, nil
}

// ImplicitMetaAnyPolicy defines an implicit meta policy whose sub_policy and key is policyname with rule ANY.
func ImplicitMetaAnyPolicy(policyName string) *StandardConfigPolicy {
	return &StandardConfigPolicy{
		key:   policyName,
		value: makeImplicitMetaPolicy(policyName, common.ImplicitMetaPolicy_ANY),
	}
}

// DefaultConfigTemplate generates a config template based on the assumption that
// the input profile is a channel creation template and no system channel context
// is available.
func DefaultConfigTemplate(conf *Profile, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	channelGroup, err := NewChannelGroup(conf, mspConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing configuration %v", err)
	}

	if _, ok := channelGroup.Groups[ApplicationGroupKey]; !ok {
		return nil, fmt.Errorf("channel template configs must contain an application section %v", err)
	}

	channelGroup.Groups[ApplicationGroupKey].Values = nil
	channelGroup.Groups[ApplicationGroupKey].Policies = nil

	return channelGroup, nil
}

// NewChannelCreateConfigUpdate generates a ConfigUpdate which can be sent to the orderer to create a new channel.  Optionally, the channel group of the
// ordering system channel may be passed in, and the resulting ConfigUpdate will extract the appropriate versions from this file.
func NewChannelCreateConfigUpdate(channelID string, conf *Profile, templateConfig *common.ConfigGroup, mspConfig *msp.MSPConfig) (*common.ConfigUpdate, error) {
	if conf.Application == nil {
		return nil, errors.New("cannot define a new channel with no Application section")
	}

	if conf.Consortium == "" {
		return nil, errors.New("cannot define a new channel with no Consortium value")
	}

	newChannelGroup, err := NewChannelGroup(conf, mspConfig)
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
		Value: MarshalOrPanic(&common.Consortium{
			Name: conf.Consortium,
		}),
	}

	return updt, nil
}

// CreateEnvelope ...
func CreateEnvelope(
	txType common.HeaderType,
	channelID string,
	dataMsg proto.Message,
	msgVersion int32,
	epoch uint64,
) (*common.Envelope, error) {

	payloadChannelHeader := MakeChannelHeader(txType, msgVersion, channelID, epoch)
	payloadSignatureHeader := &common.SignatureHeader{}

	data, err := proto.Marshal(dataMsg)
	if err != nil {
		return nil, fmt.Errorf("error marshaling %v", err)
	}

	paylBytes := MarshalOrPanic(
		&common.Payload{
			Header: MakePayloadHeader(payloadChannelHeader, payloadSignatureHeader),
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
		return nil, errors.New("refusing to generate block which has empty channel")
	}

	channelID := profile.ChannelID

	if channelID == "" {
		return nil, errors.New("refusing to generate block which has empty channel ID")
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

	ct, err := DefaultConfigTemplate(profile, mspconf)
	if err != nil {
		return nil, fmt.Errorf("could not generate default config template, %v", err)
	}

	newChannelConfigUpdate, err := NewChannelCreateConfigUpdate(channelID, profile, ct, mspconf)
	if err != nil {
		return nil, fmt.Errorf("config update generation failure %v", err)
	}

	newConfigUpdateEnv := &common.ConfigUpdateEnvelope{
		ConfigUpdate: MarshalOrPanic(newChannelConfigUpdate),
	}

	env, err := CreateEnvelope(common.HeaderType_CONFIG_UPDATE, channelID, newConfigUpdateEnv, msgVersion, epoch)

	return env, err

}
