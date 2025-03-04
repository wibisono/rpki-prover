{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE DerivingStrategies   #-}
{-# LANGUAGE DeriveGeneric        #-}
{-# LANGUAGE StrictData           #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE OverloadedLabels     #-}
{-# LANGUAGE RecordWildCards      #-}
{-# LANGUAGE FlexibleInstances    #-}

module RPKI.Http.Types where

import           Control.Lens hiding ((.=))

import qualified Data.ByteString.Lazy        as LBS
import qualified Data.ByteString.Base16      as Hex
import           Data.Text                   (Text)
import qualified Data.Text                   as Text
import           Data.Text.Encoding          (encodeUtf8)

import           Data.Aeson.Types

import           GHC.Generics                (Generic)
import qualified Data.Vector                 as V
import qualified Data.List.NonEmpty          as NonEmpty
import qualified Data.Map.Strict             as Map

import           Data.Map.Monoidal.Strict (MonoidalMap)
import qualified Data.Map.Monoidal.Strict as MonoidalMap

import           Servant.API
import           Network.HTTP.Media ((//))

import           RPKI.AppTypes
import           RPKI.Repository
import           RPKI.Domain
import           RPKI.Metrics.Metrics
import           RPKI.Orphans.Json
import           RPKI.Reporting

import           RPKI.Resources.Types
import           RPKI.Time
import           RPKI.Util (mkHash)


data ValidationsDto a = ValidationsDto {
        version     :: WorldVersion,
        timestamp   :: Instant,
        validations :: [a]
    } 
    deriving stock (Eq, Show, Generic)

data IssueDto = ErrorDto Text | WarningDto Text
    deriving stock (Eq, Show, Generic)

data FullVDto = FullVDto {
        issues  :: [IssueDto],
        path    :: [Text],
        url     :: Text
    } 
    deriving stock (Eq, Show, Generic)

newtype MinimalVDto = MinimalVDto FullVDto
    deriving stock (Eq, Show, Generic)

data VrpDto = VrpDto {
        asn       :: ASN,
        prefix    :: IpPrefix,
        maxLength :: PrefixLength,
        ta        :: Text
    } 
    deriving stock (Eq, Show, Generic)

newtype RObject = RObject (Located RpkiObject)
    deriving stock (Eq, Show, Generic)

data MetricsDto = MetricsDto {
        groupedValidations :: GroupedValidationMetric ValidationMetric,      
        rsync              :: MonoidalMap (DtoScope 'Metric) RsyncMetric,
        rrdp               :: MonoidalMap (DtoScope 'Metric) RrdpMetric
    } 
    deriving stock (Eq, Show, Generic)

data PublicationPointDto = PublicationPointDto {
        rrdp :: [(RrdpURL, RrdpRepository)]
    } 
    deriving stock (Eq, Show, Generic)
            

data ManualCVS = ManualCVS

newtype RawCVS = RawCVS { unRawCSV :: LBS.ByteString }

instance Accept ManualCVS where
    contentType _ = "text" // "csv"

instance MimeRender ManualCVS RawCVS where
    mimeRender _ = unRawCSV    

instance ToJSON RObject
instance ToJSON VrpDto     

instance ToJSON a =>  ToJSON (ValidationsDto a)

instance ToJSON FullVDto where
    toJSON FullVDto {..} = object [         
            "url"       .= url,
            "full-path" .= path,
            "issues"    .= Array (V.fromList $ issuesJson issues)
        ]      

instance ToJSON MinimalVDto where
    toJSON (MinimalVDto FullVDto {..}) = object [         
            "url"       .= url,
            "issues"    .= Array (V.fromList $ issuesJson issues)
        ]      

issuesJson :: [IssueDto] -> [Value]
issuesJson issues = flip map issues $ \case
    ErrorDto e   -> object [ "error"   .= e ]
    WarningDto w -> object [ "warning" .= w ]


newtype DtoScope (s :: ScopeKind) = DtoScope (Scope s)
    deriving stock (Show, Eq, Ord, Generic)

instance ToJSON MetricsDto
instance ToJSON RrdpURL
instance ToJSON FetchStatus
instance ToJSON RrdpRepository
instance ToJSON PublicationPointDto

instance ToJSONKey (DtoScope s) where 
    toJSONKey = toJSONKeyText $ \(DtoScope (Scope s)) -> focusToText $ NonEmpty.head s    

instance ToJSON (DtoScope s) where
    toJSON (DtoScope (Scope s)) = Array $ V.fromList $ map toJSON $ NonEmpty.toList s


toMinimalValidations :: ValidationsDto FullVDto -> ValidationsDto MinimalVDto
toMinimalValidations = (& #validations %~ map MinimalVDto)

toMetricsDto :: RawMetric -> MetricsDto
toMetricsDto rawMetrics = MetricsDto {
        groupedValidations = groupedValidationMetric rawMetrics,
        rsync   = MonoidalMap.mapKeys DtoScope $ unMetricMap $ rawMetrics ^. #rsyncMetrics,
        rrdp    = MonoidalMap.mapKeys DtoScope $ unMetricMap $ rawMetrics ^. #rrdpMetrics
    }

toPublicationPointDto :: PublicationPoints -> PublicationPointDto
toPublicationPointDto PublicationPoints {..} = PublicationPointDto {
        rrdp = Map.toList $ unRrdpMap rrdps
    }

parseHash :: Text -> Either Text Hash
parseHash hashText = bimap 
    (Text.pack . ("Broken hex: " <>) . show)
    mkHash
    $ Hex.decode $ encodeUtf8 hashText