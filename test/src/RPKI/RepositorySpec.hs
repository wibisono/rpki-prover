{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DerivingStrategies #-}

module RPKI.RepositorySpec where

import Control.Monad (replicateM)

import Data.ByteString.Short (toShort)
import Data.Maybe (maybeToList, catMaybes)
import Data.List (sort, isPrefixOf, sortOn)

import           GHC.Generics

import           Test.Tasty
import           Test.QuickCheck.Arbitrary.Generic
import qualified Test.Tasty.HUnit                  as HU
import qualified Test.Tasty.QuickCheck             as QC

import           Test.QuickCheck.Gen

import           RPKI.Domain
import           RPKI.Repository
import           RPKI.Util
import           RPKI.Orphans


repositoryGroup :: TestTree
repositoryGroup = testGroup "PublicationPoints" [
        QC.testProperty
            "RsyncNode is commutative"
            prop_rsync_tree_commutative,

        QC.testProperty
            "RsyncNode gets properly updated"
            prop_rsync_tree_update,
    
        QC.testProperty "FetchStatus is a semigroup" $ isASemigroup @FetchStatus,
        QC.testProperty "RrdpRepository is a semigroup" $ isASemigroup @RrdpRepository,
        QC.testProperty "RrdpMap is a semigroup" $ isASemigroup @RrdpMap
    ]

isASemigroup :: Eq s => Semigroup s => (s, s, s) -> Bool
isASemigroup (s1, s2, s3) = s1 <> (s2 <> s3) == (s1 <> s2) <> s3

repositoriesURIs :: [RsyncPublicationPoint]
repositoriesURIs = map (RsyncPublicationPoint . toURL) [
        "a",
        "a/b",
        "a/c",
        "a/z",
        "a/z/q",
        "a/z/q/zzz",
        "a/z/q/aa",
        "a/z/p/q",
        "b/a",
        "b/a/c",
        "a/z/q",
        "b/a/d",
        "b/a/e",
        "b/z",
        "different_root"
    ]
  where
    toURL path = let Right u = parseRsyncURL ("rsync://host1.com/" <> path) in u

prop_rsync_tree_commutative :: QC.Property
prop_rsync_tree_commutative =
    QC.forAll (replicateM 200 generateRsyncUrl) $ \urls ->
        convertToRepos (sort urls) Pending == convertToRepos urls Pending

prop_rsync_tree_update :: QC.Property
prop_rsync_tree_update =
    QC.forAll arbitrary $ \(newStatus :: FetchStatus) ->
        QC.forAll (replicateM 100 generateRsyncUrl) $ \urls ->
            QC.forAll (QC.sublistOf urls) $ \toUpdate -> let
                tree = convertToRepos urls Pending
                -- this messy stuff basically means "try to find the shortest URLs to update"
                -- and "don't update a longer one if a shorter one exists".
                allShorter = map (\(RsyncURL h p) -> 
                                    filter (\(RsyncURL h' p') -> 
                                        h == h' && p /= p' && p' `isPrefixOf` p) urls) toUpdate
                sameOrShorter =
                    zipWith (\original shorterOnes -> 
                        (case take 1 $ sortOn (\(RsyncURL _ p) -> length p) shorterOnes of
                                []   -> original
                                s :_ -> s)) 
                        toUpdate allShorter
                updatedTree = foldr (`toRsyncTree` newStatus) tree sameOrShorter
                sameOrLonger = filter (\(RsyncURL h p) -> 
                                    any (\(RsyncURL h' p') -> 
                                        h == h' && (p == p' || p' `isPrefixOf` p)) toUpdate) urls
                in all (\url -> fmap snd (statusInRsyncTree url updatedTree) == Just newStatus) sameOrLonger


convertToRepos :: [RsyncURL] -> FetchStatus -> RsyncTree
convertToRepos urls status = 
    foldr (`toRsyncTree` status) newRsyncTree urls  


generateRsyncUrl :: Gen RsyncURL
generateRsyncUrl = do
    let hosts  = [ "rrdp.ripe.net", "ca.rg.net", "rpki-repository.nic.ad.jp", "repo-rpki.idnic.net" ]
    let level1 = Nothing : map Just [ "repo", "repository", "0", "A91A73810000", "member_repository" ]
    let levelChunks = map (replicate 5) ['a'..'z']
    let level2 = replicate 5 Nothing  <> map Just levelChunks
    let level3 = replicate 10 Nothing <> map Just levelChunks
    host <- elements hosts
    pathLevels <- catMaybes <$> mapM elements [level1, level2, level3]
    let rsyncHost = RsyncHost host
    let path = map (RsyncPathChunk . convert) pathLevels
    pure $ RsyncURL rsyncHost path