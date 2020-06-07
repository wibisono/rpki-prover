{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE OverloadedLabels           #-}

module RPKI.TopDown where

import           Control.Concurrent.Async
import           Control.Concurrent.STM
import           Control.Exception
import           Control.Monad.Except
import           Control.Monad.Reader

import           Control.Lens
import           Data.Generics.Product.Typed
-- import           Data.Generics.Product.Fields

import           GHC.Generics

import           Data.Bifunctor
import           Data.Either                      (partitionEithers)
import           Data.Foldable
import           Data.Has
import           Data.List.NonEmpty               (NonEmpty (..))
import qualified Data.List.NonEmpty               as NonEmpty
import           Data.Map.Strict                  (Map)
import qualified Data.Map.Strict                  as Map
import           Data.Maybe                       (fromMaybe)
import           Data.Set                         (Set)
import qualified Data.Set                         as Set
import           Data.String.Interpolate.IsString
import qualified Data.Text                        as Text

import           RPKI.AppMonad
import           RPKI.Config
import           RPKI.Execution
import           RPKI.Domain
import           RPKI.Errors
import           RPKI.Logging
import           RPKI.Parallel
import           RPKI.Repository
import           RPKI.Resources.Resources
import           RPKI.Resources.Types
import           RPKI.RRDP.Update
import           RPKI.RRDP.Http
import           RPKI.Rsync
import           RPKI.Store.Base.Storage
import           RPKI.Store.Data
import           RPKI.Store.Repository
import           RPKI.Store.Database
import           RPKI.TAL
import           RPKI.Time
import           RPKI.Util                        (isRsyncURI, fmtEx)
import           RPKI.Version
import           RPKI.Validation.ObjectValidation


data TACertValidationResult = 
        SameTACert !CerObject !(NonEmpty Repository) |
        UpdatedTACert !CerObject !(NonEmpty Repository)
    deriving stock (Show, Eq, Generic)

storageError :: SomeException -> AppError
storageError = StorageE . StorageError . fmtEx


data Stats = Stats {
    validCount :: Int
}

newtype VRPs = VRPs (Map ASN [PrefixWithLength])
    deriving stock (Show, Eq, Generic)
    deriving newtype (Monoid)

instance Semigroup VRPs where
    VRPs v1 <> VRPs v2 = VRPs $ Map.unionWith (<>) v1 v2        

-- Auxiliarry structure used in top-down validation. It has a lot of global variables 
-- but it's lifetime is limited to one top-down validation run.
data TopDownContext s = TopDownContext {    
    verifiedResources           :: Maybe (VerifiedRS PrefixesAndAsns),

    -- Element of the queue used to asynchronously write discovered VRPs and 
    -- validation results (and potentially anything else) to the database.
    databaseQueue               :: ClosableQueue (Tx s 'RW -> IO ()),
    publicationPoints           :: TVar PublicationPoints,
    ppWaitingList               :: TVar (Map URI (Set Hash)),
    takenCareOf                 :: TVar (Set URI),
    taName                      :: TaName, 
    now                         :: Now,    
    objectStats                 :: TVar Stats,
    worldVersion                :: WorldVersion
}

createVerifiedResources :: CerObject -> VerifiedRS PrefixesAndAsns
createVerifiedResources (getRC -> ResourceCertificate certificate) = 
    VerifiedRS $ toPrefixesAndAsns $ withRFC certificate resources

makeTopDownContext :: MonadIO m => AppContext s -> TaName -> PublicationPoints -> Now -> CerObject -> m (TopDownContext s)
makeTopDownContext AppContext {..} taName publicationPoints now certificate = liftIO $ do             
    worldVersion <- getWorldVerion dynamicState
    atomically $ TopDownContext (Just $ createVerifiedResources certificate) <$> 
        createClosableQueue 100000 <*>
        newTVar publicationPoints <*>
        newTVar Map.empty <*>
        newTVar Set.empty <*>
        pure taName <*> 
        pure now <*>        
        newTVar (Stats 0) <*>
        pure worldVersion

oneMoreValid :: MonadIO m => TopDownContext s -> m ()
oneMoreValid TopDownContext {..} = liftIO $ atomically $ 
    modifyTVar' objectStats $ \s -> s { validCount = validCount s + 1 }


-- | Initial bootstrap of the TA: do everything needed to start up the validator, 
-- | * download and parse TA certificate
-- | * fetch the repositories
bootstrapTA :: Storage s => 
            AppContext s -> TAL -> IO (Either AppError (), Validations)
bootstrapTA appContext@AppContext {..} tal = do    
    runValidatorT taContext $ do         
        (nextStep, elapsed) <- timedMS $ validateTACertificateFromTAL appContext tal 
        logDebugM logger [i|Fetched and validated TA certficate #{certLocations tal}, took #{elapsed}ms.|]
        case nextStep of
            SameTACert taCert repos     -> fetchAndValidate taCert repos
            UpdatedTACert newCert repos -> fetchAndValidate newCert repos        
    where
        fetchAndValidate taCert repos = do            

            now <- thisMoment

            storedPubPoints <- roAppTxEx database storageError $ \tx -> 
                            getTaPublicationPoints tx (repositoryStore database) taName'                                            

            let reposToFetch = map fst $ 
                    -- filter the ones that are either new or need refetching
                    filter (\(pp, status) -> needsFetching pp status (config ^. typed) now) $ 
                    toRepoStatusPairs $ 
                        -- merge repos that we want with the ones that are stored                     
                        mergeRepos repos storedPubPoints
                        -- we only care about URLs from 'repos', so shrink the PPs                        
                            `shrinkTo` 
                        Set.fromList (map getURI $ NonEmpty.toList repos)

            -- logDebugM logger [i| TA: #{taName'}, 
            --     storedPubPoints = #{storedPubPoints}, 
            --     reposToFetch = #{reposToFetch} |]                               

            fetchStatuses <- parallelTasks (ioBottleneck appThreads) reposToFetch $ \repo -> do 
                logDebugM logger [i|Bootstrap, fetching #{repo} |]
                fetchRepository appContext repo

            case partitionFailedSuccess fetchStatuses of 
                ([], _) -> do
                    let flattenedStatuses = flip map fetchStatuses $ \case 
                            FetchFailure r s _ -> (r, s)
                            FetchSuccess r s _ -> (r, s)            

                    -- use publication points taken from the DB and updated with the 
                    -- the fetchStatuses of the fetch that we just performed
                    let fetchUpdatedPPs = updateStatuses storedPubPoints flattenedStatuses

                    -- logDebugM logger [i| TA: #{taName'}, fetchUpdatedPPs = #{fetchUpdatedPPs}|]       

                    topDownContext <- makeTopDownContext appContext taName' fetchUpdatedPPs now taCert
                    -- this is for TA cert
                    oneMoreValid topDownContext

                    fromTry (UnspecifiedE . fmtEx) $
                        validateCA appContext taCertURI topDownContext taCert                    

                    -- get publication points from the topDownContext and save it to the database
                    pubPointAfterTopDown <- liftIO $ readTVarIO $ publicationPoints topDownContext

                    let changeSet' = changeSet storedPubPoints pubPointAfterTopDown

                    -- logDebugM logger [i| 
                    --             ------------------------------------------------------------
                    --             TA: #{taName'} 
                    --             changeSet' = #{changeSet'},
                    --             pubPointAfterTopDown = #{pubPointAfterTopDown} 
                    --             ------------------------------------------------------------
                    --             |]  
                
                    Stats {..} <- liftIO $ readTVarIO (objectStats topDownContext)
                    logDebugM logger [i| TA: #{taName'} validCount = #{validCount} |]                                    

                    rwAppTxEx database storageError $ \tx -> 
                        applyChangeSet tx (repositoryStore database) changeSet' taName'                    

                    -- pubPointsAfterSaving <- roAppTxEx database storageError $ \tx -> 
                    --                 getTaPublicationPoints tx (repositoryStore database) taName'

                    -- logDebugM logger [i| TA: #{taName'} pubPointsAfterSaving = #{pubPointsAfterSaving} |]

                (broken, _) -> do
                    let brokenUrls = map (getURI . (^. _1)) broken
                    logErrorM logger [i|Will not proceed, repositories '#{brokenUrls}' failed to download|]
            
        taCertURI = vContext $ NonEmpty.head $ certLocations tal
        taName' = getTaName tal
        taContext = vContext $ getTaURI tal


-- | Valiidate TA starting from the TAL.
validateTACertificateFromTAL :: (Has VContext vc, Storage s) => 
                                AppContext s -> TAL -> ValidatorT vc IO TACertValidationResult
validateTACertificateFromTAL appContext@AppContext { database = DB {..}, ..} tal = do    
    (uri', ro) <- fetchTACertificate appContext tal
    newCert    <- vHoist $ validateTACert tal uri' ro      
    rwAppTxEx taStore storageError
        $ \tx -> do
            r <- getTA tx taStore taName'
            case r of
                Nothing ->
                    -- it's a new TA, store it and trigger all the other actions                    
                    storeTaCert tx newCert

                Just STA { taCert, initialRepositories } ->
                    if getSerial taCert /= getSerial newCert
                        then do            
                            logInfoM logger [i| Updating TA certificate for #{taName'} |]                            
                            storeTaCert tx newCert
                        else 
                            pure $ SameTACert taCert initialRepositories

    where        
        storeTaCert tx newCert = 
            case createRepositoriesFromTAL tal newCert of
                Left e      -> appError $ ValidationE e
                Right repos -> do 
                    putTA tx taStore (STA tal newCert repos)
                    pure $ UpdatedTACert newCert repos

        taName' = getTaName tal        
     

data FetchResult = 
    FetchSuccess !Repository !RepositoryStatus !Validations | 
    FetchFailure !Repository !RepositoryStatus !Validations
    deriving stock (Show, Eq, Generic)

-- | Download repository
fetchRepository :: (MonadIO m, Storage s) => 
                AppContext s -> Repository -> m FetchResult
fetchRepository appContext@AppContext { database = DB {..}, ..} repo = liftIO $ do
    Now now <- thisMoment
    ((r, v), elapsed) <- timedMS $ runValidatorT (vContext $ getURI repo) $ 
        case repo of
            RsyncR r -> 
                first RsyncR <$> updateObjectForRsyncRepository appContext r objectStore                                
            RrdpR r -> 
                first RrdpR <$> updateObjectForRrdpRepository appContext r objectStore                    
    case r of
        Left e -> do                        
            logErrorM logger [i|Fetching repository #{getURI repo} failed: #{e} |]
            let repoContext' = vContext $ getURI repo
            pure $ FetchFailure repo (FailedAt now) (mError repoContext' e <> v)
        Right (resultRepo, vs) -> do
            logDebugM logger [i|Fetched repository #{getURI repo}, took #{elapsed}ms.|]
            pure $ FetchSuccess resultRepo (FetchedAt now) (vs <> v)


type RepoTriple = (Repository, RepositoryStatus, Validations)

partitionFailedSuccess :: [FetchResult] -> ([RepoTriple], [RepoTriple])
partitionFailedSuccess = go
    where
        go [] = ([], [])
        go (FetchSuccess r rs v : frs) = let (fs, ss) = go frs in (fs, (r, rs, v) : ss)
        go (FetchFailure r rs v : frs) = let (fs, ss) = go frs in ((r, rs, v) : fs, ss)


validateCA :: Storage s =>
            AppContext s -> VContext -> TopDownContext s -> CerObject -> IO ()
validateCA env vContext' topDownContext certificate = do    
    let appContext@AppContext {..} = getter env
    validateCAWithQueue appContext vContext' topDownContext certificate CreateQ


data QWhat = CreateQ | AlreadyCreatedQ

validateCAWithQueue :: Storage s => 
                        AppContext s -> 
                        VContext -> 
                        TopDownContext s -> 
                        CerObject -> 
                        QWhat -> IO ()
validateCAWithQueue 
        appContext@AppContext {..} 
        vc 
        topDownContext@TopDownContext{..} 
        certificate qWhat = do 
    let certificateURL = NonEmpty.head $ getLocations certificate
    logDebugM logger [i|Starting to validate #{certificateURL}|]

    let work = do 
            (pps, validations) <- runValidatorT vc $ validateTree appContext topDownContext certificate
            queueVResult appContext topDownContext validations            
            pickUpNewPPsAndValidateDown pps

    (_, elapsed) <- timedMS $ case qWhat of 
        CreateQ -> do            
            -- Write validation results in a separate thread to avoid blocking on the 
            -- database with writing transactions during the validation process                     
            fst <$> concurrently 
                        (work `finally` atomically (closeQueue databaseQueue))
                        (executeQueuedTxs appContext topDownContext)
        
        AlreadyCreatedQ -> work
        
    logDebugM logger [i|Validated #{certificateURL}, took #{elapsed}ms.|]

    where
        -- From the set of discovered PPs figure out which must be fetched, 
        -- fetch them and validate, starting from the cerfificates in the 
        -- waiting list
        pickUpNewPPsAndValidateDown (Left _) = pure ()
        pickUpNewPPsAndValidateDown (Right discoveredPPs) = do            
            ppsToFetch <- atomically $ do 
                    globalPPs           <- readTVar publicationPoints                    
                    alreadyTakenCareOf  <- readTVar takenCareOf

                    let newGlobalPPs     = globalPPs <> discoveredPPs
                    let discoveredURIs   = allURIs discoveredPPs
                    let urisToTakeCareOf = Set.difference discoveredURIs alreadyTakenCareOf

                    writeTVar publicationPoints newGlobalPPs                                        
                    modifyTVar' takenCareOf (<> discoveredURIs) 
                    
                    pure $ newGlobalPPs `shrinkTo` urisToTakeCareOf

            let (_, rootToPps) = repositoryHierarchy discoveredPPs
                
            let newRepositories = map fst $ 
                    filter (\(pp, status) -> needsFetching pp status (config ^. typed) now) $ 
                    toRepoStatusPairs ppsToFetch

            -- for all new repositories, drill down recursively
            void $ parallelTasks (ioBottleneck appThreads) newRepositories $ \repo -> do
                validations <- fetchAndValidateWaitingList rootToPps repo
                queueVResult appContext topDownContext validations

        -- Fetch the PP and validate all the certificates from the waiting 
        -- list of this PP.
        fetchAndValidateWaitingList rootToPps repo = do
            logDebugM logger [i|Fetching #{repo} |]
            result <- fetchRepository appContext repo                                
            let statusUpdate = case result of
                    FetchFailure r s _ -> (r, s)
                    FetchSuccess r s _ -> (r, s)                

            atomically $ modifyTVar' publicationPoints $ \pubPoints -> 
                updateStatuses pubPoints [statusUpdate]            

            case result of
                FetchFailure _ _ v -> pure v 
                FetchSuccess _ _ v -> do
                    let fetchedPPs = fromMaybe Set.empty $ Map.lookup repo rootToPps
                    waitingListPerPP <- readTVarIO ppWaitingList

                    let waitingHashesForThesePPs  = fromMaybe Set.empty $ fold $ 
                            Set.map (\pp -> getURI pp `Map.lookup` waitingListPerPP) fetchedPPs

                    void $ parallelTasks 
                            (cpuBottleneck appThreads) 
                            (Set.toList waitingHashesForThesePPs) $ \hash -> do                    
                                o <- roTx database $ \tx -> getByHash tx (objectStore database) hash
                                case o of 
                                    Just (CerRO waitingCertificate) -> do
                                        -- logDebugM logger [i| #{getLocations c} was waiting for #{fetchedPPs}|]
                                        let certVContext = vContext $ NonEmpty.head $ getLocations waitingCertificate
                                        let childTopDownContext = topDownContext { 
                                                -- we should start from the resource set of this certificate
                                                -- as it is already has been verified
                                                verifiedResources = Just $ createVerifiedResources certificate
                                            }
                                        validateCAWithQueue appContext certVContext 
                                                childTopDownContext waitingCertificate AlreadyCreatedQ
                                    ro ->
                                        logErrorM logger
                                            [i| Something is really wrong with the hash #{hash} in waiting list, got #{ro}|]
                    pure v
        
    

-- | Do top-down validation starting from the given certificate
-- Returns the discovered publication points that are not registered 
-- in the top-down context yet.
validateTree :: Storage s =>
                AppContext s ->
                TopDownContext s ->
                CerObject ->                
                ValidatorT VContext IO PublicationPoints
validateTree appContext@AppContext {..} topDownContext certificate = do          
    globalPPs <- liftIO $ readTVarIO $ publicationPoints topDownContext

    let validationConfig = appContext ^. typed @Config . typed

    case publicationPointsFromCertObject certificate of
        Left e                  -> appError $ ValidationE e
        Right (u, discoveredPP) -> do
            let asIfItIsMerged = discoveredPP `mergePP` globalPPs

            let stopDescend = do 
                    -- remember to come back to this certificate when the PP ios fetched
                    certificate `addToWaitingListOf` discoveredPP
                    pure asIfItIsMerged

            case findPublicationPointStatus u asIfItIsMerged of 
                -- this publication point hasn't been seen at all, so stop here
                Nothing     -> stopDescend
                
                -- If it's been fetched too long ago, stop here and add the certificate 
                -- to the waiting list of this PP
                -- if the PP is fresh enough, proceed with the tree descend                
                Just status -> let                
                    needToRefetch = needsFetching discoveredPP status validationConfig (now topDownContext)                    
                    in if needToRefetch
                        then stopDescend 
                        else validateThisCertAndGoDown                    
    where        
        addToWaitingListOf :: CerObject -> PublicationPoint -> ValidatorT vc IO ()
        addToWaitingListOf cert pp = liftIO $ atomically $           
            modifyTVar (ppWaitingList topDownContext) $ \m -> 
                Map.unionWith (<>) m (Map.singleton (getURI pp) (Set.singleton $ getHash cert))
        
        validateThisCertAndGoDown = do
            vContext' :: VContext <- asks getVC
            let (childrenAki, locations) = (toAKI $ getSKI certificate, getLocations certificate)        

            -- this for the certificate
            oneMoreValid topDownContext

            mft <- findMft childrenAki locations
            -- this for the manifest
            oneMoreValid topDownContext                                

            forChild (NonEmpty.head $ getLocations mft) $ do
                -- logDebugM logger [i|mft=#{getLocations mft}|]

                (_, crlHash) <- case findCrlOnMft mft of 
                    []    -> vError $ NoCRLOnMFT childrenAki locations
                    [crl] -> pure crl
                    crls  -> vError $ MoreThanOneCRLOnMFT childrenAki locations crls

                let objectStore' = objectStore database
                crlObject <- liftIO $ roTx objectStore' $ \tx -> getByHash tx objectStore' crlHash
                case crlObject of 
                    Nothing          -> vError $ NoCRLExists childrenAki locations    
                    Just (CrlRO crl) -> do      

                        validCrl <- forChild (NonEmpty.head $ getLocations crl) $ do    
                            -- logDebugM logger [i|crl=#{getLocations crl}|]
                            vHoist $ do          
                                crl' <- validateCrl (now topDownContext) crl certificate
                                void $ validateMft (now topDownContext) mft certificate crl'
                                pure crl'                                        

                        -- this for the CRL
                        oneMoreValid topDownContext                        
                            
                        -- TODO Check locations and give warnings if it's wrong
                        let childrenHashes = filter ( /= getHash crl) $ -- filter out CRL itself
                                                map snd $ mftEntries $ getCMSContent $ extract mft

                        mftProblems <- parallelTasks (cpuBottleneck appThreads) childrenHashes $ \h -> do
                            ro <- roAppTx objectStore' $ \tx -> getByHash tx objectStore' h
                            case ro of 
                                Nothing  -> pure $ Left $ ManifestEntryDontExist h
                                Just ro' -> Right <$> liftIO (validateChild vContext' validCrl ro')

                        -- TODO Here we should act depending on how strict we want to be,  
                        -- Interrupt the whole thing or just continue with a warning            
                        case mftProblems of
                            [] -> pure emptyPublicationPoints
                            _  -> do 
                                let (broken, pps) = partitionEithers mftProblems
                                mapM_ vWarn broken
                                pure $! mconcat pps 

                    Just _  -> vError $ CRLHashPointsToAnotherObject crlHash locations   
    
        findMft childrenAki locations = do
            mft' <- liftIO $ roTx (objectStore database) $ \tx -> 
                findLatestMftByAKI tx (objectStore database) childrenAki
            case mft' of
                Nothing  -> vError $ NoMFT childrenAki locations
                Just mft -> pure mft

        -- TODO Is there a more reliable way to find it? Compare it with SIA?
        findCrlOnMft mft = filter (\(name, _) -> ".crl" `Text.isSuffixOf` name) $ 
            mftEntries $ getCMSContent $ extract mft

        validateChild :: VContext -> Validated CrlObject -> RpkiObject -> IO PublicationPoints
        validateChild parentContext validCrl ro = 
            case ro of
                CerRO childCert -> do 
                    let TopDownContext{..} = topDownContext
                    (r, validations) <- runValidatorT childContext $ do
                            childVerifiedResources <- vHoist $ do                 
                                    Validated validCert <- validateResourceCert now childCert certificate validCrl
                                    validateResources verifiedResources childCert validCert 
                            let childTopDownContext = topDownContext { verifiedResources = Just childVerifiedResources }
                            validateTree appContext childTopDownContext childCert 
                                    
                    queueVResult appContext topDownContext validations
                    pure $ case r of
                        Left _    -> emptyPublicationPoints
                        Right pps -> pps

                RoaRO roa -> withEmptyPPs $ do 
                    let (r, validations) = runPureValidator childContext $                                     
                                void $ validateRoa (now topDownContext) roa certificate validCrl
                    queueVResult appContext topDownContext validations
                    case r of 
                        Left _  -> pure ()
                        Right _ -> do                                
                            oneMoreValid topDownContext
                            queueVRP appContext topDownContext $ getCMSContent (extract roa :: CMS [Roa])

                GbrRO gbr -> withEmptyPPs $ do
                    z <- queueVResult appContext topDownContext $ snd $ 
                        runPureValidator childContext $ 
                            void $ validateGbr (now topDownContext) gbr certificate validCrl
                    oneMoreValid topDownContext
                    pure z
                -- TODO Anything else?
                _ -> withEmptyPPs $ pure ()
            where
                childContext = childVContext parentContext childLocation 
                childLocation = NonEmpty.head $ getLocations ro

                withEmptyPPs f = f >> pure emptyPublicationPoints


needsFetching :: Fetchable r => r -> RepositoryStatus -> ValidationConfig -> Now -> Bool
needsFetching r status ValidationConfig {..} (Now now) = 
    case status of
        New            -> True
        FetchedAt time -> tooLongAgo time
        FailedAt time  -> tooLongAgo time
    where
        tooLongAgo momendTnThePast = 
            not $ closeEnoughMoments momendTnThePast now (interval $ getFetchType r)
            where
                interval RRDP  = rrdpRepositoryRefreshInterval
                interval Rsync = rsyncRepositoryRefreshInterval


queueVRP :: Storage s => AppContext s -> TopDownContext s -> [Roa] -> IO ()
queueVRP AppContext { database = DB {..} } TopDownContext {..} roas = 
    for_ roas $ \vrp -> 
        atomically $ writeClosableQueue databaseQueue $ \tx -> 
            putVRP tx vrpStore worldVersion vrp 


-- | Put validation result into a queue for writing
queueVResult :: Storage s => AppContext s -> TopDownContext s -> Validations -> IO ()
queueVResult AppContext { database = DB {..} } TopDownContext {..} validations = do
    case validations of
        Validations validationsMap
            | emptyValidations validations -> pure ()
            | otherwise -> do
                void $ flip Map.traverseWithKey validationsMap $ 
                        \vc' problems -> 
                            let vResult = VResult (Set.toList problems) vc'   
                            in atomically $ writeClosableQueue databaseQueue $ 
                                    \tx -> putVResult tx resultStore worldVersion vResult


-- Execute writing transactions from the queue
executeQueuedTxs :: Storage s => 
            AppContext s -> TopDownContext s -> IO ()
executeQueuedTxs AppContext {..} TopDownContext {..} = do
    -- read element in chunks to make transactions not too frequent
    readQueueChunked databaseQueue 1000 $ \quuElems ->
        rwTx database $ \tx -> 
            for_ quuElems $ \f -> f tx                



completeWorldVersion :: Storage s => 
                        AppContext s -> WorldVersion -> IO ()
completeWorldVersion AppContext { database = DB {..} } worldVersion =
    rwTx versionStore $ \tx -> putVersion tx versionStore worldVersion FinishedVersion


-- | Fetch TA certificate based on TAL location(s)
fetchTACertificate :: WithVContext vc => 
                    AppContext s -> TAL -> ValidatorT vc IO (URI, RpkiObject)
fetchTACertificate appContext@AppContext {..} tal = 
    go $ NonEmpty.toList $ certLocations tal
    where
        go []         = throwError $ TAL_E $ TALError "No certificate location could be fetched."
        go (u : uris) = fetchTaCert `catchError` goToNext 
            where 
                goToNext e = do            
                    let message = [i|Failed to fetch #{u}: #{e}|]
                    logErrorM logger message
                    validatorWarning $ VWarning e
                    go uris

                fetchTaCert = do                     
                    logInfoM logger [i|Fetching TA certiicate from #{u}..|]
                    (u,) <$> fetcher appContext u
                    where
                        fetcher = if isRsyncURI u 
                                    then rsyncRpkiObject 
                                    else fetchRpkiObject



-- Utilities to have storage transaction in ValidatorT monad.
roAppTx :: (Storage s, WithStorage s ws) => 
            ws -> (Tx s 'RO -> ValidatorT env IO a) -> ValidatorT env IO a 
roAppTx s f = appTx s f roTx    

rwAppTx :: (Storage s, WithStorage s ws) => 
            ws -> (forall mode . Tx s mode -> ValidatorT env IO a) -> ValidatorT env IO a
rwAppTx s f = appTx s f rwTx


appTx :: (Storage s, WithStorage s ws) => 
        ws -> (Tx s mode -> ValidatorT env IO a) -> 
        (ws -> (Tx s mode -> IO (Either AppError a, Validations))
            -> IO (Either AppError a, Validations)) -> 
        ValidatorT env IO a
appTx s f txF = do
    env <- ask
    validatorT $ txF s $ runValidatorT env . f


roAppTxEx :: (Storage s, WithStorage s ws, Exception exc) => 
            ws -> 
            (exc -> AppError) -> 
            (Tx s 'RO -> ValidatorT env IO a) -> 
            ValidatorT env IO a 
roAppTxEx ws err f = appTxEx ws err f roTx    

rwAppTxEx :: (Storage s, WithStorage s ws, Exception exc) => 
            ws -> (exc -> AppError) -> 
            (Tx s 'RW -> ValidatorT env IO a) -> ValidatorT env IO a
rwAppTxEx s err f = appTxEx s err f rwTx

appTxEx :: (Storage s, WithStorage s ws, Exception exc) => 
            ws -> (exc -> AppError) -> 
            (Tx s mode -> ValidatorT env IO a) -> 
            (s -> (Tx s mode -> IO (Either AppError a, Validations))
               -> IO (Either AppError a, Validations)) -> 
            ValidatorT env IO a
appTxEx ws err f txF = do
    env <- ask
    -- TODO Make it less ugly and complicated
    t <- liftIO $ try $ txF (storage ws) $ runValidatorT env . f
    validatorT $ pure $ either ((, mempty) . Left . err) id t

