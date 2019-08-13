/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package privdata

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/hyperledger/fabric/common/metrics/disabled"
	util2 "github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/transientstore"
	"github.com/hyperledger/fabric/gossip/metrics"
	"github.com/hyperledger/fabric/gossip/util"
	"github.com/hyperledger/fabric/msp"
	mspmgmt "github.com/hyperledger/fabric/msp/mgmt"
	msptesttools "github.com/hyperledger/fabric/msp/mgmt/testtools"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/ledger/rwset"
	mspproto "github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/assert"
)

func init() {
	util.SetupTestLogging()
}

// type mockIdentity struct {
// 	idBytes []byte
// }
//
// func (id *mockIdentity) Anonymous() bool {
// 	panic("implement me")
// }
//
// func (id *mockIdentity) ExpiresAt() time.Time {
// 	return time.Time{}
// }
//
// func (id *mockIdentity) SatisfiesPrincipal(p *mb.MSPPrincipal) error {
// 	if bytes.Equal(id.idBytes, p.Principal) {
// 		return nil
// 	}
// 	fmt.Printf("\nidbytes: %#v\nprincipal: %#v", id.idBytes, p.Principal)
// 	return errors.New("Principals do not match")
// }
//
// func (id *mockIdentity) GetIdentifier() *msp.IdentityIdentifier {
// 	return &msp.IdentityIdentifier{Mspid: "Mock", Id: string(id.idBytes)}
// }
//
// func (id *mockIdentity) GetMSPIdentifier() string {
// 	return string(id.idBytes)
// }
//
// func (id *mockIdentity) Validate() error {
// 	return nil
// }
//
// func (id *mockIdentity) GetOrganizationalUnits() []*msp.OUIdentifier {
// 	return nil
// }
//
// func (id *mockIdentity) Verify(msg []byte, sig []byte) error {
// 	if bytes.Equal(sig, []byte("badsigned")) {
// 		return errors.New("Invalid signature")
// 	}
// 	return nil
// }
//
// func (id *mockIdentity) Serialize() ([]byte, error) {
// 	return id.idBytes, nil
// }
//
// type mockDeserializer struct {
// 	fail error
// }
//
// func (md *mockDeserializer) DeserializeIdentity(serializedIdentity []byte) (msp.Identity, error) {
// 	if md.fail != nil {
// 		return nil, md.fail
// 	}
// 	return &mockIdentity{idBytes: serializedIdentity}, nil
// }
//
// func (md *mockDeserializer) IsWellFormed(_ *mb.SerializedIdentity) error {
// 	return nil
// }
//
// type mockIterator struct {
// 	t *testing.T
// 	mock.Mock
// 	pvtReadWriteSets []*rwset.TxPvtReadWriteSet
// 	index            int
// }
//
// func (mi *mockIterator) WithPvtReadWriteSets(pvtReadWriteSets []*rwset.TxPvtReadWriteSet) {
// 	mi.index = 0
// 	mi.pvtReadWriteSets = pvtReadWriteSets
// }
//
// func (mi *mockIterator) Next() (*transientstore.EndorserPvtSimulationResults, error) {
// 	panic("implement me")
// }
//
// func (mi *mockIterator) NextWithConfig() (*transientstore.EndorserPvtSimulationResultsWithConfig, error) {
// 	if mi.index > len(mi.pvtReadWriteSets) {
// 		mi.index = 0
// 		return nil, nil
// 	}
// 	res := &transientstore.EndorserPvtSimulationResultsWithConfig{
// 		ReceivedAtBlockHeight: 1,
// 		PvtSimulationResultsWithConfig: &transientstoreprotos.TxPvtReadWriteSetWithConfigInfo{
// 			PvtRwset: mi.pvtReadWriteSets[mi.index],
// 		},
// 	}
// 	mi.index++
// 	return res, nil
// }
//
// func (mi *mockIterator) Close() {
// }

func TestPvtdataProviderRetreivePrivateData(t *testing.T) {
	identity := protoutil.MarshalOrPanic(&mspproto.MSPRole{
		MspIdentifier: "org1",
		Role:          mspproto.MSPRole_MEMBER,
	})
	peerSelfSignedData := protoutil.SignedData{
		Identity:  identity,
		Signature: []byte{3, 4, 5},
		Data:      []byte{6, 7, 8},
	}
	channelID := util2.GetTestChainID()
	blockNum := uint64(1)
	storePvtDataOfInvalidTx := true
	metrics := metrics.NewGossipMetrics(&disabled.Provider{}).PrivdataMetrics
	// purgedTxns := make(map[string]struct{})

	tempdir, err := ioutil.TempDir("", "ts")
	if err != nil {
		t.Fatalf("Failed to create test directory: %s", err)
	}

	storeProvider := transientstore.NewStoreProvider(tempdir)
	store, err := storeProvider.OpenStore(channelID)
	defer storeProvider.Close()
	defer os.RemoveAll(tempdir)
	// store := &mockTransientStore{t: t}
	// iterator := &mockIterator{t: t}
	// store.On("PurgeByTxids", mock.Anything).Run(func(args mock.Arguments) {
	// 	for _, txn := range args.Get(0).([]string) {
	// 		purgedTxns[txn] = struct{}{}
	// 	}
	// }).Return(nil)
	// store.On("GetTxPvtRWSetByTxid", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
	// }).Return(iterator, nil)
	// assertPurged := func(txns ...string) {
	// 	for _, txn := range txns {
	// 		_, exists := purgedTxns[txn]
	// 		assert.True(t, exists)
	// 		delete(purgedTxns, txn)
	// 	}
	// 	assert.Len(t, purgedTxns, 0)
	// }

	expectedBlockPvtdata := ledger.BlockPvtdata{
		PvtData:        make(ledger.TxPvtDataMap),
		MissingPvtData: make(ledger.TxMissingPvtDataMap),
	}

	fetcher := &fetcherMock{t: t}
	err = msptesttools.LoadMSPSetupForTesting()
	assert.NoError(t, err)
	idDeserializerFactory := IdentityDeserializerFactoryFunc(func(chainID string) msp.IdentityDeserializer {
		return mspmgmt.GetManagerForChain(channelID)
	})
	// mockIDDeserializerFactory := &privdatamock.IdentityDeserializerFactory{}
	// mockIDDeserializerFactory.GetIdentityDeserializerReturns(&mockDeserializer{})

	hash := util2.ComputeSHA256([]byte("rws-pre-image"))

	// block := bf.AddTxnWithEndorsement("tx1", "ns1", hash, "org1", true, "c1", "c2").
	// 	AddTxnWithEndorsement("tx2", "ns2", hash, "org2", true, "c1").create()
	pvtReadWriteSets := []*rwset.TxPvtReadWriteSet{
		&rwset.TxPvtReadWriteSet{
			NsPvtRwset: []*rwset.NsPvtReadWriteSet{
				&rwset.NsPvtReadWriteSet{
					Namespace: "ns1",
					CollectionPvtRwset: []*rwset.CollectionPvtReadWriteSet{
						&rwset.CollectionPvtReadWriteSet{
							CollectionName: "c1",
							Rwset:          []byte("rws-pre-image"),
						},
						&rwset.CollectionPvtReadWriteSet{
							CollectionName: "c2",
							Rwset:          []byte("rws-pre-image"),
						},
					},
				},
			},
		},
		&rwset.TxPvtReadWriteSet{
			NsPvtRwset: []*rwset.NsPvtReadWriteSet{
				&rwset.NsPvtReadWriteSet{
					Namespace: "ns2",
					CollectionPvtRwset: []*rwset.CollectionPvtReadWriteSet{
						&rwset.CollectionPvtReadWriteSet{
							CollectionName: "c1",
							Rwset:          []byte("rws-pre-image"),
						},
					},
				},
			},
		},
	}

	pvtdataCollections := &util.PvtDataCollections{
		&ledger.TxPvtData{
			SeqInBlock: 1,
			WriteSet:   pvtReadWriteSets[0],
		},
		&ledger.TxPvtData{
			SeqInBlock: 2,
			WriteSet:   pvtReadWriteSets[1],
		},
	}
	// iterator.WithPvtReadWriteSets(pvtReadWriteSets)

	fmt.Println("Scenario I")
	// Scenario I: Block we got has sufficient private data alongside it.

	// pvtData := pdFactory.addRWSet().addNSRWSet("ns1", "c1", "c2").addRWSet().addNSRWSet("ns2", "c1").create()
	txPvtdataInfo := []*ledger.TxPvtdataInfo{
		&ledger.TxPvtdataInfo{
			TxID:       "tx1",
			SeqInBlock: 1,
			CollectionPvtdataInfo: []*ledger.CollectionPvtdataInfo{
				&ledger.CollectionPvtdataInfo{
					Collection:   "c1",
					Namespace:    "ns1",
					ExpectedHash: hash,
					Endorsers: []*peer.Endorsement{
						&peer.Endorsement{
							Signature: []byte("org1"),
						},
					},
					CollectionConfig: &common.StaticCollectionConfig{
						Name:           "c1",
						MemberOnlyRead: true,
						MemberOrgsPolicy: &common.CollectionPolicyConfig{
							Payload: &common.CollectionPolicyConfig_SignaturePolicy{
								SignaturePolicy: &common.SignaturePolicyEnvelope{
									Rule: &common.SignaturePolicy{
										Type: &common.SignaturePolicy_SignedBy{
											SignedBy: 0,
										},
									},
									Identities: []*mspproto.MSPPrincipal{
										&mspproto.MSPPrincipal{
											PrincipalClassification: mspproto.MSPPrincipal_ROLE,
											Principal: protoutil.MarshalOrPanic(&mspproto.MSPRole{
												MspIdentifier: "SampleOrg",
												Role:          mspproto.MSPRole_MEMBER,
											}),
										},
									},
								},
							},
						},
					},
				},
				&ledger.CollectionPvtdataInfo{
					Collection:   "c2",
					Namespace:    "ns1",
					ExpectedHash: hash,
					Endorsers: []*peer.Endorsement{
						&peer.Endorsement{
							Signature: []byte("org2"),
						},
					},
					CollectionConfig: &common.StaticCollectionConfig{
						Name: "c2",
						MemberOrgsPolicy: &common.CollectionPolicyConfig{
							Payload: &common.CollectionPolicyConfig_SignaturePolicy{
								SignaturePolicy: &common.SignaturePolicyEnvelope{
									Rule: &common.SignaturePolicy{
										Type: &common.SignaturePolicy_SignedBy{
											SignedBy: 0,
										},
									},
									Identities: []*mspproto.MSPPrincipal{
										&mspproto.MSPPrincipal{
											PrincipalClassification: mspproto.MSPPrincipal_ROLE,
											Principal: protoutil.MarshalOrPanic(&mspproto.MSPRole{
												MspIdentifier: "SampleOrg",
												Role:          mspproto.MSPRole_MEMBER,
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		&ledger.TxPvtdataInfo{
			TxID:       "tx2",
			SeqInBlock: 2,
			CollectionPvtdataInfo: []*ledger.CollectionPvtdataInfo{
				&ledger.CollectionPvtdataInfo{
					Collection:   "c1",
					Namespace:    "ns2",
					ExpectedHash: hash,
					Endorsers: []*peer.Endorsement{
						&peer.Endorsement{
							Signature: []byte("org1"),
						},
					},
					CollectionConfig: &common.StaticCollectionConfig{
						Name: "c1",
						MemberOrgsPolicy: &common.CollectionPolicyConfig{
							Payload: &common.CollectionPolicyConfig_SignaturePolicy{
								SignaturePolicy: &common.SignaturePolicyEnvelope{
									Rule: &common.SignaturePolicy{
										Type: &common.SignaturePolicy_SignedBy{
											SignedBy: 0,
										},
									},
									Identities: []*mspproto.MSPPrincipal{
										&mspproto.MSPPrincipal{
											PrincipalClassification: mspproto.MSPPrincipal_ROLE,
											Principal: protoutil.MarshalOrPanic(&mspproto.MSPRole{
												MspIdentifier: "SampleOrg",
												Role:          mspproto.MSPRole_MEMBER,
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	pdp := NewPvtdataProvider(
		peerSelfSignedData,
		metrics,
		store,
		testConfig.PullRetryThreshold,
		*pvtdataCollections,
		testConfig.TransientBlockRetention,
		channelID,
		blockNum,
		storePvtDataOfInvalidTx,
		fetcher,
		idDeserializerFactory,
	)
	blockPvtdata, err := pdp.RetrievePrivatedata(txPvtdataInfo)
	assert.NoError(t, err)
	assert.NotEqual(t, expectedBlockPvtdata, blockPvtdata)
	// assertPurged("tx1", "tx2")

	// Scenario II: Fetch private data from cache
	// Scenario III: Fetch private data from transient store
	// Scenario IV: Fetch private data from peer
}

func TestPvtdataProviderFailedToRetreivePrivateData(t *testing.T) {
	peerSelfSignedData := protoutil.SignedData{
		Identity:  []byte{0, 1, 2},
		Signature: []byte{3, 4, 5},
		Data:      []byte{6, 7, 8},
	}
	metrics := metrics.NewGossipMetrics(&disabled.Provider{}).PrivdataMetrics
	store := &mockTransientStore{t: t}
	channelID := "test"
	blockNum := uint64(1)
	storePvtDataOfInvalidTx := true
	txPvtdataInfo := []*ledger.TxPvtdataInfo{
		&ledger.TxPvtdataInfo{},
	}
	pvtdataCollections := &util.PvtDataCollections{}
	fetcher := &fetcherMock{t: t}
	idDeserializerFactory := IdentityDeserializerFactoryFunc(func(chainID string) msp.IdentityDeserializer {
		return mspmgmt.GetManagerForChain(channelID)
	})
	// mockIDDeserializerFactory := &privdatamock.IdentityDeserializerFactory{}
	// mockIDDeserializerFactory.GetIdentityDeserializerReturns(&mockDeserializer{})

	// Scenario I: Failed to retreive private data from cache
	pdp := NewPvtdataProvider(
		peerSelfSignedData,
		metrics,
		store,
		testConfig.PullRetryThreshold,
		*pvtdataCollections,
		testConfig.TransientBlockRetention,
		channelID,
		blockNum,
		storePvtDataOfInvalidTx,
		fetcher,
		idDeserializerFactory,
	)
	_, err := pdp.RetrievePrivatedata(txPvtdataInfo)
	assert.NoError(t, err)
	// assert.EqualError(t, err, "Could not find txID for SeqInBlock 1")

	// Scenario II: Failed to list missing private data in cache
	// Scenario III: Failed to fetch private data from transient store
	// Scenario IV: Failed to fetch private data from peers
}
