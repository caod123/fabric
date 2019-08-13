/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package privdata

import (
	"encoding/hex"
	"fmt"
	"time"

	vsccErrors "github.com/hyperledger/fabric/common/errors"
	commonutil "github.com/hyperledger/fabric/common/util"
	pvtdatasc "github.com/hyperledger/fabric/core/common/privdata"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/gossip/metrics"
	pvtdatacommon "github.com/hyperledger/fabric/gossip/privdata/common"
	"github.com/hyperledger/fabric/gossip/util"
	"github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protoutil"
)

type pvtdataProviderImpl struct {
	selfSignedData          protoutil.SignedData
	metrics                 *metrics.PrivdataMetrics
	transientStore          TransientStore
	pullRetryThreshold      time.Duration
	pvtdataCollections      util.PvtDataCollections
	blockPvtdata            ledger.BlockPvtdata
	privateInfo             *privateDataInfo
	transientBlockRetention uint64
	channelID               string
	blockNum                uint64
	storePvtDataOfInvalidTx bool
	idDeserializerFactory   IdentityDeserializerFactory

	Fetcher
}

func NewPvtdataProvider(
	selfSignedData protoutil.SignedData,
	metrics *metrics.PrivdataMetrics,
	transientStore TransientStore,
	pullRetryThreshold time.Duration,
	pvtdataCollections util.PvtDataCollections,
	transientBlockRetention uint64,
	channelID string,
	blockNum uint64,
	storePvtDataOfInvalidTx bool,
	fetcher Fetcher,
	idDeserializerFactory IdentityDeserializerFactory,
) ledger.BlockPvtdataProvider {
	blockPvtdata := ledger.BlockPvtdata{
		PvtData:        make(ledger.TxPvtDataMap),
		MissingPvtData: make(ledger.TxMissingPvtDataMap),
	}
	pvtdataProvider := &pvtdataProviderImpl{
		metrics:                 metrics,
		transientStore:          transientStore,
		pullRetryThreshold:      pullRetryThreshold,
		pvtdataCollections:      pvtdataCollections,
		blockPvtdata:            blockPvtdata,
		transientBlockRetention: transientBlockRetention,
		channelID:               channelID,
		blockNum:                blockNum,
		storePvtDataOfInvalidTx: storePvtDataOfInvalidTx,
		Fetcher:                 fetcher,
		idDeserializerFactory:   idDeserializerFactory,
		selfSignedData:          selfSignedData,
	}

	return pvtdataProvider
}

// RetrievePvtdata retrieves the private data for the given txs containing private data
func (pdp *pvtdataProviderImpl) RetrievePrivatedata(txPvtdataInfo []*ledger.TxPvtdataInfo) (ledger.BlockPvtdata, error) {
	listMissingStart := time.Now()
	pvtdata, err := pdp.fetchPvtdataFromCache(txPvtdataInfo)
	if err != nil {
		logger.Warning("Failed fetching pvt data from cache", err)
		return pdp.blockPvtdata, err
	}

	err = pdp.listMissingPvtdata(pvtdata, txPvtdataInfo)
	if err != nil {
		logger.Warning(err)
		return pdp.blockPvtdata, err
	}

	pdp.reportListMissingPvtdataDuration(time.Since(listMissingStart))

	err = pdp.fetchPvtdataFromTransientStore(pvtdata)
	if err != nil {
		logger.Warning("Failed fetching pvt data from transient store", err)
		return pdp.blockPvtdata, err
	}

	retryThresh := pdp.pullRetryThreshold
	var bFetchFromPeers bool // defaults to false
	if len(pdp.privateInfo.missingKeys) == 0 {
		logger.Debugf("[%s] No missing collection private write sets to fetch from remote peers", pdp.channelID)
	} else {
		bFetchFromPeers = true
		logger.Debugf("[%s] Could not find all collection private write sets in local peer transient store for block [%d].", pdp.channelID, pdp.blockNum)
		logger.Debugf("[%s] Fetching %d collection private write sets from remote peers for a maximum duration of %s", pdp.channelID, len(pdp.privateInfo.missingKeys), retryThresh)
	}
	startPull := time.Now()
	limit := startPull.Add(retryThresh)
	for len(pdp.privateInfo.missingKeys) > 0 && time.Now().Before(limit) {
		err = pdp.fetchPvtdataFromPeers(pvtdata)
		// If succeeded to fetch everything, no need to sleep before
		// retry
		if err != nil {
			logger.Warning("Failed fetching pvt data from peers", err)
			return pdp.blockPvtdata, err
		}
		if len(pdp.privateInfo.missingKeys) == 0 {
			break
		}
		time.Sleep(pullRetrySleepInterval)
	}
	elapsedPull := int64(time.Since(startPull) / time.Millisecond) // duration in ms

	pdp.reportFetchDuration(time.Since(startPull))

	// Only log results if we actually attempted to fetch
	if bFetchFromPeers {
		if len(pdp.privateInfo.missingKeys) == 0 {
			logger.Infof("[%s] Fetched all missing collection private write sets from remote peers for block [%d] (%dms)", pdp.channelID, pdp.blockNum, elapsedPull)
		} else {
			logger.Warningf("[%s] Could not fetch all missing collection private write sets from remote peers. Will commit block [%d] with missing private write sets:[%v]",
				pdp.channelID, pdp.blockNum, pdp.privateInfo.missingKeys)
		}
	}

	pdp.getBlockPvtdata(pvtdata, txPvtdataInfo)
	return pdp.blockPvtdata, nil

}

// Done purges transactions in the block
func (pdp *pvtdataProviderImpl) Done() {
	purgeStart := time.Now()

	if len(pdp.blockPvtdata.PvtData) > 0 {
		// Finally, purge all transactions in block - valid or not valid.
		if err := pdp.transientStore.PurgeByTxids(pdp.privateInfo.txns); err != nil {
			logger.Error("Purging transactions", pdp.privateInfo.txns, "failed:", err)
		}
	}

	seq := pdp.blockNum
	if seq%pdp.transientBlockRetention == 0 && seq > pdp.transientBlockRetention {
		err := pdp.transientStore.PurgeByHeight(seq - pdp.transientBlockRetention)
		if err != nil {
			logger.Error("Failed purging data from transient store at block", seq, ":", err)
		}
	}

	pdp.reportPurgeDuration(time.Since(purgeStart))
}

func (pdp *pvtdataProviderImpl) fetchPvtdataFromCache(txPvtdataInfo []*ledger.TxPvtdataInfo) (rwsetByKeys, error) {
	pvtdataFromCache := make(map[rwSetKey][]byte)

	for _, txPvtdata := range pdp.pvtdataCollections {
		txID := GetTxIDBySeqInBlock(txPvtdata.SeqInBlock, txPvtdataInfo)
		if txID == "" {
			err := fmt.Errorf("Could not find txID for SeqInBlock %d", txPvtdata.SeqInBlock)
			return nil, err
		}
		for _, ns := range txPvtdata.WriteSet.NsPvtRwset {
			for _, col := range ns.CollectionPvtRwset {
				computedHash := hex.EncodeToString(commonutil.ComputeSHA256(col.Rwset))
				pvtdataFromCache[rwSetKey{
					txID:       txID,
					seqInBlock: txPvtdata.SeqInBlock,
					collection: col.CollectionName,
					namespace:  ns.Namespace,
					hash:       computedHash,
				}] = col.Rwset
			} // iterate over collections in the namespace
		} // iterate over the namespaces in the WSet
	} // iterate over the transactions in the block
	return pvtdataFromCache, nil
}

// listMissingPrvtdata identifies missing private write sets and attempts to retrieve them from local transient store
func (pdp *pvtdataProviderImpl) listMissingPvtdata(pvtdata rwsetByKeys, txPvtdataInfo []*ledger.TxPvtdataInfo) error {
	sources := make(map[rwSetKey][]*peer.Endorsement)
	privateRWsetsInBlock := make(map[rwSetKey]struct{})
	missing := make(rwSetKeysByTxIDs)
	missingRWSButIneligible := make(rwSetKeysByTxIDs)

	var txList []string
	for _, txPvtdata := range txPvtdataInfo {
		txID := txPvtdata.TxID
		seqInBlock := txPvtdata.SeqInBlock
		txList = append(txList, txID)
		for _, colInfo := range txPvtdata.CollectionPvtdataInfo {
			ns := colInfo.Namespace
			col := colInfo.Collection
			hash := colInfo.ExpectedHash
			endorsers := colInfo.Endorsers
			colConfig := colInfo.CollectionConfig

			// If an error occurred due to the unavailability of database, we should stop committing
			// blocks for the associated chain. The policy can never be nil for a valid collection.
			// For collections which were never defined, the policy would be nil and we can safely
			// move on to the next collection.
			deserializer := pdp.idDeserializerFactory.GetIdentityDeserializer(pdp.channelID)
			policy, err := pvtdatasc.NewSimpleCollection(colConfig, deserializer)
			if _, isNoSuchCollectionError := err.(pvtdatasc.NoSuchCollectionError); err != nil && !isNoSuchCollectionError {
				logger.Errorf("Failed obtaining policy for collection, channel [%s], chaincode [%s], "+
					"collection name [%s], txID [%s] due to database unavailability:", pdp.channelID, ns, col, txID)
				return &vsccErrors.VSCCExecutionFailureError{Err: err}
			}
			fmt.Printf("\npolicy: %#v\n", policy)

			if policy == nil {
				logger.Errorf("Failed to retrieve collection config for channel [%s], chaincode [%s], collection name [%s] for txID [%s]. Skipping.",
					pdp.channelID, ns, col, txID)
				continue
			}

			key := rwSetKey{
				txID:       txID,
				seqInBlock: seqInBlock,
				hash:       string(hash),
				namespace:  ns,
				collection: col,
			}

			txAndSeq := txAndSeqInBlock{
				txID:       txID,
				seqInBlock: seqInBlock,
			}
			if !policy.AccessFilter()(pdp.selfSignedData) {
				logger.Debugf("Peer is not eligible for collection, channel [%s], chaincode [%s], "+
					"collection name [%s], txID [%s] the policy is [%#v]. Skipping.",
					pdp.channelID, ns, col, txID, policy)
				missingRWSButIneligible[txAndSeq] = append(missingRWSButIneligible[txAndSeq], key)
				fmt.Printf("\nnot eligible\n")
				continue
			}

			privateRWsetsInBlock[key] = struct{}{}
			if _, exists := pvtdata[key]; !exists {
				missing[txAndSeq] = append(missing[txAndSeq], key)
				sources[key] = endorsersFromOrgs(ns, col, endorsers, policy.MemberOrgs())
			}
		}
	}

	pdp.privateInfo = &privateDataInfo{
		sources:                        sources,
		missingKeysByTxIDs:             missing,
		txns:                           txList,
		missingRWSButIneligibleByTxIDs: missingRWSButIneligible,
		privateRWsetsInBlock:           privateRWsetsInBlock,
	}

	return nil
}

func (pdp *pvtdataProviderImpl) fetchPvtdataFromTransientStore(pvtdata rwsetByKeys) error {
	logger.Debug("Retrieving private write sets for", len(pdp.privateInfo.missingKeysByTxIDs), "transactions from transient store")

	// Put into pvtdata RW sets that are missing and found in the transient store
	for txAndSeq, filter := range pdp.privateInfo.missingKeysByTxIDs.FiltersByTxIDs() {
		iterator, err := pdp.transientStore.GetTxPvtRWSetByTxid(txAndSeq.txID, filter)
		if err != nil {
			logger.Warning("Failed obtaining iterator from transient store:", err)
			return err
		}
		defer iterator.Close()
		for {
			res, err := iterator.NextWithConfig()
			if err != nil {
				logger.Error("Failed iterating:", err)
				return err
			}
			if res == nil {
				// End of iteration
				break
			}
			if res.PvtSimulationResultsWithConfig == nil {
				logger.Warning("Resultset's PvtSimulationResultsWithConfig for", txAndSeq.txID, "is nil, skipping")
				continue
			}
			simRes := res.PvtSimulationResultsWithConfig
			if simRes.PvtRwset == nil {
				logger.Warning("The PvtRwset of PvtSimulationResultsWithConfig for", txAndSeq.txID, "is nil, skipping")
				continue
			}
			for _, ns := range simRes.PvtRwset.NsPvtRwset {
				for _, col := range ns.CollectionPvtRwset {
					key := rwSetKey{
						txID:       txAndSeq.txID,
						seqInBlock: txAndSeq.seqInBlock,
						collection: col.CollectionName,
						namespace:  ns.Namespace,
						hash:       hex.EncodeToString(commonutil.ComputeSHA256(col.Rwset)),
					}
					// populate the pvtdata with the RW set from the transient store
					pvtdata[key] = col.Rwset
				} // iterating over all collections
			} // iterating over all namespaces
		} // iterating over the TxPvtRWSet results
	}

	// In the end, iterate over the pvtdata, and if the key doesn't exist in
	// the privateRWsetsInBlock - delete it from the pvtdata
	for k := range pvtdata {
		if _, exists := pdp.privateInfo.privateRWsetsInBlock[k]; !exists {
			logger.Warning("Removed", k.namespace, k.collection, "hash", k.hash, "from the data passed to the ledger")
			delete(pvtdata, k)
		}
	}

	pdp.privateInfo.missingKeys = pdp.privateInfo.missingKeysByTxIDs.flatten()
	// Remove all keys we already own
	pdp.privateInfo.missingKeys.exclude(func(key rwSetKey) bool {
		_, exists := pvtdata[key]
		return exists
	})

	return nil
}

func (pdp *pvtdataProviderImpl) fetchPvtdataFromPeers(pvtdata rwsetByKeys) error {
	dig2src := make(map[pvtdatacommon.DigKey][]*peer.Endorsement)
	pdp.privateInfo.missingKeys.foreach(func(k rwSetKey) {
		logger.Debug("Fetching", k, "from peers")
		dig := pvtdatacommon.DigKey{
			TxId:       k.txID,
			SeqInBlock: k.seqInBlock,
			Collection: k.collection,
			Namespace:  k.namespace,
			BlockSeq:   pdp.blockNum,
		}
		dig2src[dig] = pdp.privateInfo.sources[k]
	})
	fetchedData, err := pdp.fetch(dig2src)
	if err != nil {
		logger.Warning("Failed fetching private data for block", pdp.blockNum, "from peers:", err)
		return err
	}

	// Iterate over data fetched from peers
	for _, element := range fetchedData.AvailableElements {
		dig := element.Digest
		for _, rws := range element.Payload {
			hash := hex.EncodeToString(commonutil.ComputeSHA256(rws))
			key := rwSetKey{
				txID:       dig.TxId,
				namespace:  dig.Namespace,
				collection: dig.Collection,
				seqInBlock: dig.SeqInBlock,
				hash:       hash,
			}
			if _, isMissing := pdp.privateInfo.missingKeys[key]; !isMissing {
				logger.Debug("Ignoring", key, "because it wasn't found in the block")
				continue
			}
			pvtdata[key] = rws
			delete(pdp.privateInfo.missingKeys, key)
			// If we fetch private data that is associated to block i, then our last block persisted must be i-1
			// so our ledger height is i, since blocks start from 0.
			err := pdp.transientStore.Persist(dig.TxId, pdp.blockNum, key.toTxPvtReadWriteSet(rws))
			if err != nil {
				logger.Warning("Failed to persist private write set for key [%s] to tranisent store", key)
			}
			logger.Debug("Fetched", key)
		}
	}
	// Iterate over purged data
	for _, dig := range fetchedData.PurgedElements {
		// delete purged key from missing keys
		for missingPvtRWKey := range pdp.privateInfo.missingKeys {
			if missingPvtRWKey.namespace == dig.Namespace &&
				missingPvtRWKey.collection == dig.Collection &&
				missingPvtRWKey.txID == dig.TxId {
				delete(pdp.privateInfo.missingKeys, missingPvtRWKey)
				logger.Warningf("Missing key because was purged or will soon be purged, "+
					"continue block commit without [%+v] in private rwset", missingPvtRWKey)
			}
		}
	}

	return nil
}

func (pdp *pvtdataProviderImpl) reportListMissingPvtdataDuration(time time.Duration) {
	pdp.metrics.ListMissingPrivateDataDuration.With("channel", pdp.channelID).Observe(time.Seconds())
}

func (pdp *pvtdataProviderImpl) reportFetchDuration(time time.Duration) {
	pdp.metrics.FetchDuration.With("channel", pdp.channelID).Observe(time.Seconds())
}

func (pdp *pvtdataProviderImpl) reportPurgeDuration(time time.Duration) {
	pdp.metrics.PurgeDuration.With("channel", pdp.channelID).Observe(time.Seconds())
}

func (pdp *pvtdataProviderImpl) getBlockPvtdata(pvtdata rwsetByKeys, txPvtdataQuery []*ledger.TxPvtdataInfo) {
	for _, txPvtdata := range txPvtdataQuery {
		seqInBlock := txPvtdata.SeqInBlock

		// add all found pvtdata to blockPvtDataPvtdata for seqInBlock
		if nsRWS, found := pvtdata.bySeqsInBlock()[seqInBlock]; found {
			pdp.blockPvtdata.PvtData[seqInBlock] = &ledger.TxPvtData{
				SeqInBlock: seqInBlock,
				WriteSet:   nsRWS.toRWSet(),
			}
		}

		// add all missing pvtdata to blockPvtData.MissingPvtData for seqInBlock
		for _, colPvtdataInfo := range txPvtdata.CollectionPvtdataInfo {
			key := rwSetKey{
				txID:       txPvtdata.TxID,
				seqInBlock: seqInBlock,
				namespace:  colPvtdataInfo.Namespace,
				collection: colPvtdataInfo.Collection,
				hash:       string(colPvtdataInfo.ExpectedHash),
			}
			if pdp.privateInfo.missingKeys.Contains(key) {
				pdp.blockPvtdata.MissingPvtData.Add(seqInBlock, colPvtdataInfo.Namespace, colPvtdataInfo.Collection, true)
			} else if pdp.privateInfo.missingRWSButIneligible.Contains(key) {
				pdp.blockPvtdata.MissingPvtData.Add(seqInBlock, colPvtdataInfo.Namespace, colPvtdataInfo.Collection, false)
			}
		}
	}

	return
}

func GetTxIDBySeqInBlock(seqInBlock uint64, txPvtdataInfo []*ledger.TxPvtdataInfo) string {
	for _, txPvtdata := range txPvtdataInfo {
		if txPvtdata.SeqInBlock == seqInBlock {
			return txPvtdata.TxID
		}
	}

	return ""
}
