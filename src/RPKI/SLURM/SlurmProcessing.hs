{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StrictData         #-}
{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE OverloadedLabels   #-}
{-# LANGUAGE QuasiQuotes        #-}
{-# LANGUAGE RecordWildCards    #-}

module RPKI.SLURM.SlurmProcessing where


import Control.Lens ( (^.) )
import Control.Monad

import qualified Data.ByteString.Lazy as LBS

import           Data.Bifunctor
import qualified Data.Text as Text

import           Data.Maybe (fromMaybe)
import           Data.List (nub)
import           Data.Coerce

import qualified Data.Set as Set
import qualified Data.Map.Monoidal.Strict as MonoidalMap

import           Data.Aeson as Json

import           Data.String.Interpolate.IsString

import           Data.These

import           RPKI.AppMonad
import           RPKI.Domain
import           RPKI.Reporting
import           RPKI.Resources.Types
import           RPKI.Resources.Resources (prefixLen)

import           RPKI.SLURM.Types

import RPKI.Util (fmtEx)


slurmVrpName :: TaName
slurmVrpName = TaName "slurm"

-- TODO BgpSec stuff is not supported at the moment.

applySlurm :: Slurm -> Vrps -> Vrps
applySlurm slurm (Vrps vrps) = 
    Vrps $ filteredVrps <> MonoidalMap.singleton slurmVrpName assertedVrps
  where     
    filteredVrps = MonoidalMap.map (Set.filter filterFunc) vrps

    assertedVrps = Set.fromList 
        $ map toVrp 
        $ slurm ^. #locallyAddedAssertions . #prefixAssertions
      where
        toVrp PrefixAssertion {..} = 
            Vrp (coerce asn) prefix (fromMaybe (prefixLen prefix) maxPrefixLength)

    filterFunc (Vrp vAsn vPrefix _) = 
            not 
            $ any matchesFilter 
            $ slurm ^. #validationOutputFilters . #prefixFilters
      where
        matchesFilter z = case z ^. #asnAndPrefix of
            This asn         -> coerce asn == vAsn
            That prefix      -> vPrefix `isInsideOf` prefix
            These asn prefix -> coerce asn == vAsn && vPrefix `isInsideOf` prefix
        
        isInsideOf (Ipv4P pS) (Ipv4P pB) = pB `contains` pS
        isInsideOf (Ipv6P pS) (Ipv6P pB) = pB `contains` pS
        isInsideOf _ _                   = False
    

readSlurmFiles :: [String] -> ValidatorT IO Slurm
readSlurmFiles slurmFiles = do 
    slurms :: [Slurm] <- 
        forM slurmFiles $ \f -> do
            s <- fromTry (SlurmE . SlurmFileError (Text.pack f) . fmtEx) $ LBS.readFile f
            vHoist $ fromEither 
                   $ first (SlurmE . SlurmParseError (Text.pack f) . Text.pack) 
                   $ Json.eitherDecode s
        
    vHoist $ validateNoOverlaps $ zip slurmFiles slurms
    pure $! mconcat slurms        


{- Validate overlappings as described in
    https://datatracker.ietf.org/doc/html/rfc8416#section-4.2

    This one implement the most naive and inefficient O(N^2) check,
-}
validateNoOverlaps :: [(String, Slurm)] -> PureValidatorT ()
validateNoOverlaps slurms = do 
    let prefixes = [ (fileName, assertPrefixes <> filterPrefixes) |                        
                (fileName, slurm) <- slurms,
                let assertPrefixes = map (^. #prefix) $ slurm ^. #locallyAddedAssertions . #prefixAssertions,
                let filterPrefixes = [ prefix | 
                            prefixFilter <- slurm ^. #validationOutputFilters . #prefixFilters,
                            That prefix  <- [ prefixFilter ^. #asnAndPrefix ]
                        ]
            ]

    checkNoPrefixOverlap prefixes

    let asns = [ (fileName, assertAsns <> filterAsns) |                        
                (fileName, slurm) <- slurms,
                let assertAsns = map (coerce . (^. #asn)) 
                        $ slurm ^. #locallyAddedAssertions . #bgpsecAssertions,
                let filterAsns = [ coerce asn | 
                            bgpsecFilter <- slurm ^. #validationOutputFilters . #bgpsecFilters,
                            This asn <- [ bgpsecFilter ^. #asnAndSKI ]
                        ]
            ]      

    checkNoASNOverlap asns                 

  where
    checkNoPrefixOverlap :: [(String, [IpPrefix])] -> PureValidatorT ()
    checkNoPrefixOverlap [] = pure ()
    checkNoPrefixOverlap ((f, ps) : rest) = do         
        let overlappings = filter (not . null . snd) $ map (second (prefixOverlaps ps)) rest
        if null overlappings 
            then checkNoPrefixOverlap rest
            else do 
                let fmt file overlaps' = [i|File #{f} has prefix overlaps with file #{file}: #{overlaps'}|]
                appError $ SlurmE $ SlurmValidationError 
                        $ mconcat $ map (uncurry fmt) overlappings         

    checkNoASNOverlap :: [(String, [ASN])] -> PureValidatorT ()
    checkNoASNOverlap [] = pure ()
    checkNoASNOverlap ((f, as) : rest) = do         
        let overlappings = filter (any (`elem` as) . snd) rest
        if null overlappings 
            then checkNoASNOverlap rest
            else do 
                let fmt file overlaps' = [i|File #{f} has ASN overlaps with file #{file}: #{overlaps'}|]
                appError $ SlurmE $ SlurmValidationError 
                        $ mconcat $ map (uncurry fmt) overlappings  

    prefixOverlaps :: [IpPrefix] -> [IpPrefix] -> [(IpPrefix, IpPrefix)]    
    -- Since `overlap p1 p2 == overlap p2 p1` we only want to report one of them
    prefixOverlaps ps1 ps2 = nub [ if p1 < p2 then (p1, p2) else (p2, p1) | 
                                p1 <- ps1, p2 <- ps2, overlap p1 p2 ]
      where
        overlap (Ipv4P p1) (Ipv4P p2) = not $ null $ p1 `intersection` p2
        overlap (Ipv6P p1) (Ipv6P p2) = not $ null $ p1 `intersection` p2
        overlap _ _                   = False        

