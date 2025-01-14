{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE StrictData            #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE QuasiQuotes           #-}

module RPKI.Http.Messages where

import           Data.Text                   (Text)
import qualified Data.Text                   as Text
import qualified Data.List                   as List

import           Data.String.Interpolate.IsString
import           Data.Tuple.Strict

import           RPKI.Domain                 as Domain
import           RPKI.Reporting
import           RPKI.Util (fmtLocations)
import Data.ASN1.Types (OID)


toMessage :: AppError -> Text
toMessage = \case
    ParseE (ParseError t) -> t
    ValidationE v -> toValidationMessage v    
    RrdpE r  -> toRrdpMessage r
    RsyncE r -> toRsyncMessage r
    TAL_E (TALError t) -> t
    InitE (InitError t) -> t    
    
    StorageE (StorageError t) -> t
    StorageE (DeserialisationError t) -> t

    SlurmE r    -> toSlurmMessage r
    InternalE t -> toInternalErrorMessage t
    
    UnspecifiedE context e -> 
        [i|Unspecified error #{context}, details: #{e}.|]


toRsyncMessage :: RsyncError -> Text
toRsyncMessage = \case 
    RsyncProcessError errorCode e ->
        [i|Rsync client returned code #{errorCode}, error = #{e}.|]

    FileReadError e ->
        [i|Can't read local file created by rsync client #{e}.|]

    RsyncRunningError e ->
        [i|Error running rsync client #{e}.|]

    RsyncDownloadTimeout t ->
        [i|Could not update repository in #{t}s.|]

    UnknownRsyncProblem e ->
        [i|Unknown problem with rsync #{e}.|]


toRrdpMessage :: RrdpError -> Text
toRrdpMessage = \case
    BrokenXml t    -> [i|XML parsing error: #{t}.|]
    BrokenSerial s -> [i|Malformed serial number: #{s}.|]
    NoSessionId    -> [i|Session ID is not set.|]
    NoSerial       -> [i|Serial number is not set.|]
    NoSnapshotHash -> [i|Snapshot hash is not set.|]
    NoSnapshotURI  -> [i|Snapshot URL is not set.|]
    NoDeltaSerial  -> [i|Delta serial is not set.|]
    NoDeltaURI     -> [i|Delta URL is not set.|]
    NoDeltaHash    -> [i|Delta hash is not set.|]
    BadHash h      -> [i|String #{h} is not a valid SHA256 hash.|]
    NoVersion      -> [i|RRDP version is not set.|]  
    BadVersion v   -> [i|String #{v} is not a valid RRDP version.|]  
    NoPublishURI   -> [i|An "publish" element doesn't have URL attribute.|]  

    BadBase64 base64 url -> [i|Base64 #{base64} for URL #{url} is invalid.|]  

    BadURL u -> [i|Unsupported or invalid URL #{u}.|]  

    NoHashInWithdraw -> [i|No "hash" attribute in a "withdraw" element.|]  

    ContentInWithdraw url _ -> 
        [i|Content inside of "withdraw" element with url #{url}.|]  

    LocalSerialBiggerThanRemote local remote -> 
        [i|Local RRDP serial is #{local} higher than the remote #{remote}.|]  

    NonConsecutiveDeltaSerials deltaPairs ->           
        [i|Non-consecutive deltas: #{mconcat (map show deltaPairs)}.|]  

    CantDownloadFile e -> [i|Cannot download file: #{e}.|]  

    CantDownloadNotification e -> [i|Cannot download notification.xml: #{e}.|]  

    CantDownloadSnapshot e -> [i|Cannot download snapshot #{e}.|]  
    CantDownloadDelta e    -> [i|Cannot download delta #{e}.|]  

    SnapshotHashMismatch {..} -> 
        [i|Snapshot hash is #{actualHash} but required hash is #{expectedHash}.|]  

    SnapshotSessionMismatch {..} -> 
        [i|Snapshot session ID is #{actualSessionId} but required hash is #{expectedSessionId}.|]  

    SnapshotSerialMismatch {..} -> 
        [i|Snapshot serial is #{actualSerial} but required hash is #{expectedSerial}.|]  

    DeltaHashMismatch {..} -> 
        [i|Delta #{serial} hash is #{actualHash} but required hash is #{expectedHash}.|]  

    DeltaSessionMismatch {..} -> 
        [i|Delta's session ID is #{actualSessionId} but required session ID is #{expectedSessionId}.|]  

    DeltaSerialMismatch {..} -> 
        [i|Delta serial is #{actualSerial} but required serial is #{expectedSerial}.|]        

    DeltaSerialTooHigh {..} -> 
        [i|Delta serial #{actualSerial} is larger than maximal expected #{expectedSerial}.|]        
    
    NoObjectToReplace url hash -> 
        [i|No object with url #{url} and hash #{hash} to replace.|]        

    NoObjectToWithdraw url hash ->
        [i|No object with url #{url} and hash #{hash} to withdraw.|]        

    ObjectExistsWhenReplacing url hash -> 
        [i|Cannot replace object with url #{url}: object with hash #{hash} already exists.|]        

    UnsupportedObjectType url -> 
        [i|Unsupported object type #{url}.|]        
        
    RrdpDownloadTimeout t -> 
        [i|Could not update repository in #{t}s.|]        

    UnknownRrdpProblem e -> 
        [i|Unknown problem with RRDP: #{e}.|]  


toValidationMessage :: ValidationError -> Text
toValidationMessage = \case      
      SPKIMismatch (EncodedBase64 talPKI) (EncodedBase64 actualPKI) -> 
          [i|Mismatch between subject public key info in the TAL #{talPKI} and the actual one #{actualPKI}.|]

      UnknownObjectAsTACert -> 
          [i|TA certificate is not a certificate, but some other object.|]

      ObjectIsTooSmall s -> [i|Object is too small (#{s} bytes) for a valid RPKI object.|]
      ObjectIsTooBig s   -> [i|Object is too big (#{s} bytes) for a valid RPKI object.|]

      InvalidSignature e -> [i|Object signature is invalid, error: #{e}.|]
      InvalidKI e       -> [i|Certificate SKI is invalid, error: #{e}.|]

      CMSSignatureAlgorithmMismatch sigEE sigAttr -> 
          [i|Signature algorithm on the EE certificate is #{sigEE} but the CSM attributes says #{sigAttr}.|]

      TACertAKIIsNotEmpty u -> [i|TA certificate #{u} has an AKI.|]

      CertNoPolicyExtension -> [i|Certificate has no policy extension.|]
          
      CertBrokenExtension oid b -> [i|Certificate extension #{fmtOID oid} is broken: #{b}.|]
      UnknownCriticalCertificateExtension oid b -> [i|Unknown critical certificate extension, OID: #{fmtOID  oid}, content #{b}.|]
      MissingCriticalExtension oid -> [i|Missing critical certificate extension #{fmtOID oid}.|]
      BrokenKeyUsage t -> [i|Broken keyUsage extension: #{t}.|]

      ObjectHasMultipleLocations locs -> 
          [i|The same object has multiple locations #{fmtUrlList locs}, this is suspicious.|]

      NoMFT aki _ -> 
          [i|No manifest found for #{aki}.|]

      NoCRLOnMFT aki _ -> 
          [i|No CRL found on the manifest manifest found for AKI #{aki}.|]

      MoreThanOneCRLOnMFT aki locations entries ->
          [i|Multiple CRLs #{fmtMftEntries entries} found on the manifest manifest found for AKI #{aki} for CA #{fmtLocations locations}.|]

      NoMFTSIA locations -> 
          [i|No SIA pointing to the manifest on the certificate #{fmtLocations locations}.|]

      MFTOnDifferentLocation url locations -> 
          [i|Manifest location #{url} is not the same as SIA on the certificate #{fmtLocations locations}.|]

      BadFileNameOnMFT filename message -> 
            [i|File #{filename} is malformed #{message}.|]

      NonUniqueManifestEntries nonUniqueEntries -> 
            [i|File #{fmtBrokenMftEntries nonUniqueEntries}.|]

      NoCRLExists aki locations -> 
            [i|No CRL exists with AKI #{aki} for CA #{fmtLocations locations}.|]

      CRLOnDifferentLocation crlDP locations -> 
          [i|CRL distribution point #{crlDP} is not the same as CRL location #{fmtLocations locations}.|]

      CRLHashPointsToAnotherObject hash locations -> 
          [i|CRL hash #{hash} points to different object for CA #{fmtLocations locations}.|]

      NextUpdateTimeNotSet -> 
          [i|Next update time is not set.|]

      NextUpdateTimeIsInThePast {..} -> 
          [i|Next update time #{nextUpdateTime} is in the past (current time is #{now}).|]

      ThisUpdateTimeIsInTheFuture {..} -> 
          [i|This update time #{thisUpdateTime} is in the future (current time is #{now}).|]

      RevokedResourceCertificate -> 
          [i|Object's EE certificate is revoked.|]

      CertificateIsInTheFuture {..} -> 
          [i|Certificate's 'not valid before' time #{before} is in the future.|]

      CertificateIsExpired {..} ->
          [i|Certificate is expired, its 'not valid after' time #{after} is in the past.|]

      AKIIsNotEqualsToParentSKI childAKI parentSKI ->
          [i|Certificate's AKI #{childAKI} is not the same as its parent's SKI #{parentSKI}.|]

      ManifestEntryDoesn'tExist hash filename -> 
          [i|Manifest entry #{filename} with hash #{hash} not found.|]

      OverclaimedResources resources -> 
          [i|Certificate (or EE) claims resources #{resources} not present on parent certificate.|]

      InheritWithoutParentResources -> 
          [i|Certificate has 'inherit' as resource set, but its parent doesn't have resources.|]

      UnknownUriType url -> 
          [i|URL type is neither rsync nor RRDP, #{url}.|]          

      BrokenUri url e -> 
          [i|Error #{e} parsing URL #{url}.|]          

      CertificateDoesntHaveSIA -> 
          [i|Certificate doesn't have SIA with publication point.|]

      CircularReference hash locations ->
          [i|Object with hash #{hash} and location #{fmtLocations locations} creates reference cycle.|]

      CertificatePathTooDeep locations maxDepth ->
          [i|The CA tree reached maximum depth of #{maxDepth} at #{locations}.|]

      TreeIsTooBig locations maxTreeSize ->          
          [i|The number of object in CA tree reached maximum of #{maxTreeSize} at #{locations}.|]

      TooManyRepositories locations maxTaRepositories ->          
          [i|The number of new repositories added by one TA reached maximum of #{maxTaRepositories} at #{locations}.|]

      ValidationTimeout maxDuration -> 
          [i|Validation did not finish within #{maxDuration}s and was interrupted.|]

      ManifestLocationMismatch filename locations -> 
          [i|Object has manifest entry #{filename}, but was found at the different location #{fmtLocations locations}.|]

      InvalidVCardFormatInGbr e -> [i|Invalid VCard format: #{e}.|]

      RoaPrefixIsOutsideOfResourceSet roaPrefix resources -> 
          [i|ROA prefix #{roaPrefix} is not inside of the EE certificate resources #{resources}.|]

      RoaPrefixLenghtsIsBiggerThanMaxLength (Vrp _ prefix maxLength) -> 
          [i|VRP is malformed, length of the prefix #{prefix} is bigger than #{maxLength}.|]
  where
    fmtUrlList = mconcat . 
                 List.intersperse "," . map show  

    fmtMftEntries = mconcat . 
                    List.intersperse "," . 
                    map (\(T2 t h) -> t <> Text.pack (":" <> show h))

    fmtBrokenMftEntries = mconcat . 
                    List.intersperse "," . 
                    map (\(h, fs) -> Text.pack $ "Hash: " <> show h <> " -> " <> show fs)


toSlurmMessage :: SlurmError -> Text
toSlurmMessage = \case 
    SlurmFileError file t  -> [i|Failed to read SLURM file #{file}: #{t}.|]
    SlurmParseError file t -> [i|Failed to parse SLURM file #{file}: #{t}.|]
    SlurmValidationError t -> [i|Invalid SLURM file(s): #{t}.|]

toInternalErrorMessage :: InternalError -> Text
toInternalErrorMessage = \case 
    InternalError t     -> t
    WorkerTimeout t     -> t
    WorkerOutOfMemory t -> t

fmtOID :: OID -> Text
fmtOID oid = Text.intercalate "." $ map (Text.pack . show) oid