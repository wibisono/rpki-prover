{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE StrictData            #-}
{-# LANGUAGE OverloadedStrings     #-}

module RPKI.Store.Types where

import           Codec.Serialise
import           Data.Int
import qualified Data.ByteString.Short    as BSS

import           GHC.Generics
import           RPKI.Domain
import           RPKI.TAL

import           RPKI.Time                (Instant)

import           RPKI.Repository
import           RPKI.AppTypes
import           RPKI.Store.Base.Storable


data StorableTA = StorableTA {
    tal                 :: TAL,
    taCert              :: CerObject,
    fetchStatus         :: FetchStatus,
    initialRepositories :: PublicationPointAccess
} deriving (Show, Eq, Generic, Serialise)

data ROMeta = ROMeta {
        insertedBy :: WorldVersion,
        validatedBy :: Maybe WorldVersion
    } 
    deriving stock (Show, Eq, Generic)
    deriving anyclass (Serialise)

data MftTimingMark = MftTimingMark Instant Instant 
    deriving stock (Show, Eq, Ord, Generic)
    deriving anyclass (Serialise)

newtype UrlKey = UrlKey ArtificialKey
    deriving stock (Show, Eq, Ord, Generic)
    deriving anyclass (Serialise)

newtype ObjectKey = ObjectKey ArtificialKey
    deriving stock (Show, Eq, Ord, Generic)
    deriving anyclass (Serialise)

newtype ArtificialKey = ArtificialKey Int64
    deriving stock (Show, Eq, Ord, Generic)
    deriving anyclass (Serialise)

newtype SafeUrlAsKey = SafeUrlAsKey BSS.ShortByteString 
    deriving stock (Show, Eq, Ord, Generic)
    deriving anyclass (Serialise)        

data RpkiObjectStats = RpkiObjectStats {
    objectsStats       :: SStats,
    mftByAKIStats      :: SStats,    
    hashToKeyStats     :: SStats,
    lastValidMftStats  :: SStats,
    uriToUriKeyStat    :: SStats,
    uriKeyToUriStat    :: SStats,
    uriKeyToObjectKeyStat  :: SStats,
    objectKeyToUrlKeysStat :: SStats,
    objectInsertedByStats  :: SStats,
    objectValidatedByStats  :: SStats    
} deriving stock (Show, Eq, Generic)

data VResultStats = VResultStats {     
    resultsStats :: SStats    
} deriving  (Show, Eq, Generic)

data RepositoryStats = RepositoryStats {
    rrdpStats  :: SStats,
    rsyncStats :: SStats,
    lastSStats :: SStats    
} deriving stock (Show, Eq, Generic)

data DBStats = DBStats {
    taStats         :: SStats,
    repositoryStats :: RepositoryStats,
    rpkiObjectStats :: RpkiObjectStats,    
    vResultStats    :: VResultStats,    
    vrpStats        :: SStats,        
    metricsStats    :: SStats,    
    versionStats    :: SStats,    
    sequenceStats   :: SStats,
    slurmStats      :: SStats
} deriving stock (Show, Eq, Generic)

data TotalDBStats = TotalDBStats {
    dbStats :: DBStats,
    total   :: SStats    
} deriving stock (Show, Eq, Generic)