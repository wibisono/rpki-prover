{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedLabels  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}


module RPKI.RRDP.RrpdFetch where

import           Control.Lens                     ((^.))
import           Control.Monad.Except
import           Control.Exception.Lifted (finally)
import           Control.Monad.Reader.Class
import           Data.Generics.Product.Typed

import           Data.Bifunctor                   (first)
import qualified Data.ByteString.Lazy             as LBS
import qualified Data.List                        as List
import           Data.String.Interpolate.IsString

import           GHC.Generics

import           RPKI.AppContext
import           RPKI.AppMonad
import           RPKI.Config
import           RPKI.Domain
import           RPKI.Errors
import           RPKI.Logging
import           RPKI.Parallel
import           RPKI.Parse.Parse
import           RPKI.Repository
import           RPKI.RRDP.Http
import           RPKI.RRDP.HttpContext
import           RPKI.RRDP.Parse
import           RPKI.RRDP.Types
import           RPKI.Store.Base.Storable
import           RPKI.Store.Base.Storage
import qualified RPKI.Store.Database              as DB
import           RPKI.Time
import qualified RPKI.Util                        as U
import           RPKI.Version

import           Data.IORef.Lifted

import qualified Streaming.Prelude                as S

import           System.Mem                       (performGC)



-- | 
--  Update RRDP repository, i.e. do the full cycle
--    - download notifications file, parse it
--    - decide what to do next based on it
--    - download snapshot or deltas
--    - do something appropriate with either of them
-- 
downloadAndUpdateRRDP :: WithVContext vc => 
                AppContext s ->
                HttpContext ->
                RrdpRepository ->                 
                (Notification -> LBS.ByteString -> ValidatorT vc IO Validations) ->
                (Notification -> LBS.ByteString -> ValidatorT vc IO Validations) ->
                ValidatorT vc IO (RrdpRepository, Validations)
downloadAndUpdateRRDP 
        appContext
        httpContext
        repo@(RrdpRepository repoUri _ _)      
        handleSnapshotBS                       -- ^ function to handle the snapshot bytecontent
        handleDeltaBS =                        -- ^ function to handle delta bytecontents
    do
    (notificationXml, _) <- fromTry (RrdpE . CantDownloadNotification . U.fmtEx) $ 
                                downloadToLazyBS httpContext rrdpConf (getURL repoUri)     
    notification         <- hoistHere $ parseNotification notificationXml
    nextStep             <- hoistHere $ rrdpNextStep repo notification

    case nextStep of
        NothingToDo                         -> pure (repo, mempty)
        UseSnapshot snapshotInfo            -> useSnapshot snapshotInfo notification            
        UseDeltas sortedDeltas snapshotInfo -> 
                useDeltas sortedDeltas notification
                    `catchError` 
                \e -> do         
                    -- NOTE At the moment we ignore the fact that some objects are wrongfully added
                    logErrorM logger [i|Failed to apply deltas for #{repoUri}: #{e}, will fall back to snapshot.|]
                    appWarn e
                    useSnapshot snapshotInfo notification            
    where        
        hoistHere = vHoist . fromEither . first RrdpE
                
        rrdpConf = appContext ^. typed @Config . typed @RrdpConf
        logger   = appContext ^. typed @AppLogger
        ioBottleneck = appContext ^. typed @AppBottleneck . #ioBottleneck

        useSnapshot (SnapshotInfo uri hash) notification = 
            forChild (U.convert uri) $ do       
                logDebugM logger [i|#{uri}: downloading snapshot.|]
                (r, v, downloadedIn, savedIn) <- downloadAndSave
                logDebugM logger [i|#{uri}: downloaded in #{downloadedIn}ms and saved snapshot in #{savedIn}ms.|]                        
                pure (r, v)
            where                     
                downloadAndSave = do
                    ((rawContent, _), downloadedIn) <- timedMS $ 
                            fromTryEither (RrdpE . CantDownloadSnapshot . U.fmtEx) $ 
                                    downloadHashedLazyBS httpContext rrdpConf uri hash                                    
                                        (\actualHash -> Left $ RrdpE $ SnapshotHashMismatch hash actualHash)
                    (validations, savedIn) <- timedMS $ handleSnapshotBS notification rawContent            
                    pure (repo { rrdpMeta = rrdpMeta' }, validations, downloadedIn, savedIn)   

                rrdpMeta' = Just (notification ^. #sessionId, notification ^. #serial)

        useDeltas sortedDeltas notification = do
            let repoURI = getURL $ repo ^. #uri
            logDebugM logger [i|#{repoURI}: downloading deltas from #{minSerial} to #{maxSerial}.|]

            -- Try to deallocate all the bytestrings created by mmaps right after they are used, 
            -- otherwise they will hold too much files open.
            (r, elapsed) <- timedMS $ downloadAndSave `finally` liftIO performGC

            logDebugM logger [i|#{repoURI}: downloaded and saved deltas, took #{elapsed}ms.|]                        
            pure r
            where
                downloadAndSave = do
                    -- TODO Do not thrash the same server with too big amount of parallel 
                    -- requests, it's mostly counter-productive and rude. Maybe 8 is still too much.         
                    localRepoBottleneck <- liftIO $ newBottleneckIO 8            
                    validations <- foldPipeline
                                        (localRepoBottleneck <> ioBottleneck)
                                        (S.each sortedDeltas)
                                        downloadDelta
                                        (\rawContent validations -> 
                                            (validations <>) <$> handleDeltaBS notification rawContent)
                                        (mempty :: Validations)
                    
                    pure (repo { rrdpMeta = rrdpMeta' }, validations)                    

                downloadDelta (DeltaInfo uri hash serial) = do
                    (rawContent, _) <- fromTryEither (RrdpE . CantDownloadDelta . U.fmtEx) $ 
                                            downloadHashedLazyBS httpContext rrdpConf uri hash
                                                (\actualHash -> Left $ RrdpE $ DeltaHashMismatch hash actualHash serial)
                    pure rawContent

                serials = map (^. typed @Serial) sortedDeltas
                maxSerial = List.maximum serials
                minSerial = List.minimum serials
                rrdpMeta' = Just (notification ^. typed @SessionId, maxSerial)


data Step
  = UseSnapshot SnapshotInfo
  | UseDeltas
      { sortedDeltas :: [DeltaInfo]
      , snapshotInfo :: SnapshotInfo
      }
  | NothingToDo
  deriving (Show, Eq, Ord, Generic)



-- | Decides what to do next based on current state of the repository
-- | and the parsed notification file
rrdpNextStep :: RrdpRepository -> Notification -> Either RrdpError Step
rrdpNextStep (RrdpRepository _ Nothing _) Notification{..} = 
    Right $ UseSnapshot snapshotInfo
rrdpNextStep (RrdpRepository _ (Just (repoSessionId, repoSerial)) _) Notification{..} =
    if  | sessionId /= repoSessionId -> Right $ UseSnapshot snapshotInfo
        | repoSerial > serial        -> Left $ LocalSerialBiggerThanRemote repoSerial serial
        | repoSerial == serial       -> Right NothingToDo
        | otherwise ->
            case (deltas, nonConsecutive) of
                ([], _) -> Right $ UseSnapshot snapshotInfo
                (_, []) | nextSerial repoSerial < head (map deltaSerial sortedDeltas) ->
                            -- we are too far behind
                            Right $ UseSnapshot snapshotInfo
                        | otherwise ->
                            Right $ UseDeltas chosenDeltas snapshotInfo
                (_, nc) -> Left $ NonConsecutiveDeltaSerials nc
            where
                sortedSerials = map deltaSerial sortedDeltas
                sortedDeltas = List.sortOn deltaSerial deltas
                chosenDeltas = filter ((> repoSerial) . deltaSerial) sortedDeltas

                nonConsecutive = List.filter (\(s, s') -> nextSerial s /= s') $
                    List.zip sortedSerials (tail sortedSerials)


deltaSerial :: DeltaInfo -> Serial
deltaSerial (DeltaInfo _ _ s) = s

nextSerial :: Serial -> Serial
nextSerial (Serial s) = Serial $ s + 1


-- | 
--  Update RRDP repository, actually saving all the objects in the DB.
--
-- NOTE: It will update the sessionId and serial of the repository 
-- in the same transaction it stores the data in.
-- 
updateObjectForRrdpRepository :: Storage s => 
                                AppContext s ->
                                RrdpRepository ->
                                ValidatorT vc IO (RrdpRepository, Validations)
updateObjectForRrdpRepository appContext@AppContext {..} repository = do        
        stats <- liftIO newRrdpStat
        (r, v) <- downloadAndUpdateRRDP 
                appContext 
                httpContext
                repository 
                (saveSnapshot appContext stats)  
                (saveDelta appContext stats)          
        RrdpStat {..} <- liftIO $ completeRrdpStat stats
        let repoURI = getURL $ repository ^. #uri
        logDebugM logger [i|Downloaded #{repoURI}, added #{added} objects, ignored removals of #{removed}.|]
        pure (r, v)


{- Snapshot case, done in parallel by two thread
    - one thread parses XML, reads base64s and pushes CPU-intensive parsing tasks into the queue 
    - another thread read parsing tasks, waits for them and saves the results into the DB.
-} 
saveSnapshot :: Storage s => 
                AppContext s -> 
                RrdpStatWork ->
                Notification ->
                LBS.ByteString -> 
                ValidatorT vc IO Validations
saveSnapshot appContext rrdpStats notification snapshotContent = do  
    parentContext <- asks getVC         
    worldVersion  <- liftIO $ getWorldVerion $ appContext ^. typed @Versions
    doSaveObjects parentContext worldVersion 
  where
    doSaveObjects parentContext worldVersion = do
        -- TODO check that the session_id and serial are the same as in the notification file
        (Snapshot _ sessionId serial snapshotItems) <- vHoist $ 
            fromEither $ first RrdpE $ parseSnapshot snapshotContent

        let notificationSessionId = notification ^. typed @SessionId
        when (sessionId /= notificationSessionId) $ 
            appError $ RrdpE $ SnapshotSessionMismatch sessionId notificationSessionId

        let notificationSerial = notification ^. typed @Serial
        when (serial /= notificationSerial) $ 
            appError $ RrdpE $ SnapshotSerialMismatch serial notificationSerial

        -- split into writing transactions of 10000 elements to make them always finite 
        -- and independent from the size of the snapshot.
        fromTry 
            (StorageE . StorageError . U.fmtEx)    
            (txFoldPipeline 
                cpuParallelism
                (S.mapM newStorable $ S.each snapshotItems)
                (rwTx objectStore)     
                saveStorable
                (mempty :: Validations))                 
      where
        newStorable (SnapshotPublish uri encodedb64) =             
            if supportedExtension $ U.convert uri 
                then do 
                    task <- readBlob `pureTask` bottleneck
                    pure $ Right (uri, task)
                else 
                    pure $ Left (UnsupportedObjectType, uri)
            where 
                readBlob = case U.parseRpkiURL $ unURI uri of
                    Left e        -> SError $ RrdpE $ BadURL $ U.convert e
                    Right rpkiURL -> parseAndProcess rpkiURL encodedb64
                                
        saveStorable _ (Left (e, uri)) validations = do
            let vc = childVC (unURI uri) parentContext
            pure $ validations <> mWarning vc (VWarning $ RrdpE e)

        saveStorable tx (Right (uri, a)) validations = do
            let vc = childVC (unURI uri) parentContext
            waitTask a >>= \case                        
                SError e   -> do
                    logError_ logger [i|Couldn't parse object #{uri}, error #{e} |]
                    pure $ validations <> mError vc e
                SObject so -> do 
                    DB.putObject tx objectStore so worldVersion
                    addedOne rrdpStats
                    pure validations

    logger         = appContext ^. typed @AppLogger           
    cpuParallelism = appContext ^. typed @Config . typed @Parallelism . #cpuParallelism
    bottleneck     = appContext ^. typed @AppBottleneck . #cpuBottleneck
    objectStore    = appContext ^. #database . #objectStore


{-
    The same as snapshots but takes base64s from ordered 
    list of deltas.
-}
saveDelta :: Storage s => 
            AppContext s 
            -> RrdpStatWork 
            -> Notification 
            -> LBS.ByteString 
            -> ValidatorT conf IO Validations
saveDelta appContext rrdpStats notification deltaContent = do        
    parentContext <- asks getVC
    worldVersion  <- liftIO $ getWorldVerion $ appContext ^. typed @Versions
    doSaveObjects parentContext worldVersion
  where
    doSaveObjects parentContext worldVersion = do
        Delta _ sessionId serial deltaItems <- 
            vHoist $ fromEither $ first RrdpE $ parseDelta deltaContent    

        let notificationSessionId = notification ^. typed @SessionId
        when (sessionId /= notificationSessionId) $ 
            appError $ RrdpE $ DeltaSessionMismatch sessionId notificationSessionId

        let notificationSerial = notification ^. typed @Serial
        when (serial > notificationSerial) $ 
            appError $ RrdpE $ DeltaSerialTooHigh serial notificationSerial

        let deltaItemS = S.each deltaItems
        fromTry (StorageE . StorageError . U.fmtEx) 
            (txFoldPipeline 
                cpuParallelism
                (S.mapM newStorable deltaItemS)
                (rwTx objectStore) 
                saveStorable
                (mempty :: Validations))
      where
        newStorable (DP (DeltaPublish uri hash encodedb64)) =
            if supportedExtension $ U.convert uri 
                then do 
                    task <- readBlob `pureTask` bottleneck
                    pure $ Right $ maybe (Add uri task) (Replace uri task) hash
                else 
                    pure $ Left (UnsupportedObjectType, uri)
            where 
                readBlob = case U.parseRpkiURL $ unURI uri of
                    Left e        -> SError $ RrdpE $ BadURL $ U.convert e
                    Right rpkiURL -> parseAndProcess rpkiURL encodedb64

        newStorable (DW (DeltaWithdraw _ hash)) = 
            pure $ Right $ Delete hash

        saveStorable _ (Left (e, uri)) validations = do
            let vc = childVC (unURI uri) parentContext
            pure $ validations <> mWarning vc (VWarning $ RrdpE e)

        saveStorable tx (Right op) validations =
            case op of
                Delete _                  -> do
                    -- Ignore withdraws and just use the time-based garbage collection
                    -- DB.deleteObject tx objectStore hash
                    pure validations
                Add uri async'             -> addObject tx uri async' validations
                Replace uri async' oldHash -> replaceObject tx uri async' oldHash validations                    
        
        addObject tx uri a validations =
            waitTask a >>= \case
                SError e -> do                    
                    logError_ logger [i|Couldn't parse object #{uri}, error #{e} |]
                    let vc = childVC (unURI uri) parentContext
                    pure $ validations <> mError vc e
                SObject so@(StorableObject ro _) -> do
                    alreadyThere <- DB.hashExists tx objectStore (getHash ro)
                    unless alreadyThere $ do
                        DB.putObject tx objectStore so worldVersion                      
                        addedOne rrdpStats
                    pure validations

        replaceObject tx uri a oldHash validations = do
            let vc = childVC (unURI uri) parentContext
            waitTask a >>= \case
                SError e -> do                    
                    logError_ logger [i|Couldn't parse object #{uri}, error #{e} |]                    
                    pure $ validations <> mError vc e
                SObject so@(StorableObject ro _) -> do        
                    oldOneIsAlreadyThere <- DB.hashExists tx objectStore oldHash                           
                    validations' <- if oldOneIsAlreadyThere 
                        then do 
                            -- Ignore withdraws and just use the time-based garbage collection
                            removedOne rrdpStats
                            pure validations
                        else do 
                            logWarn_ logger [i|No object #{uri} with hash #{oldHash} to replace.|]
                            pure $ validations <> mWarning vc
                                (VWarning $ RrdpE $ NoObjectToReplace uri oldHash) 

                    newOneIsAlreadyThere <- DB.hashExists tx objectStore (getHash ro)
                    unless newOneIsAlreadyThere $ do                            
                        DB.putObject tx objectStore so worldVersion
                        addedOne rrdpStats
                    pure validations'                                                                                    

    logger         = appContext ^. typed @AppLogger           
    cpuParallelism = appContext ^. typed @Config . typed @Parallelism . #cpuParallelism
    bottleneck     = appContext ^. typed @AppBottleneck . #cpuBottleneck                      
    objectStore    = appContext ^. #database . #objectStore


parseAndProcess :: RpkiURL -> EncodedBase64 -> StorableUnit RpkiObject AppError
parseAndProcess u b64 =     
    case parsed of
        Left e   -> SError e
        Right ro -> SObject $! toStorableObject ro                    
    where
        parsed = do
            DecodedBase64 b <- first RrdpE $ decodeBase64 b64 u
            first ParseE $ readObject u b    

data DeltaOp m a = Delete !Hash 
                | Add !URI !(Task m a) 
                | Replace !URI !(Task m a) !Hash


data DeltaLog a = DeleteLog !Hash 
                | AddLog !URI !SValue
                | ReplaceLog !URI !Hash !SValue

data RrdpStat = RrdpStat {
    added   :: !Int,
    removed :: !Int
}

data RrdpStatWork = RrdpStatWork {
    added   :: IORef Int,
    removed :: IORef Int
}

completeRrdpStat :: RrdpStatWork -> IO RrdpStat
completeRrdpStat RrdpStatWork {..} = 
    RrdpStat <$> readIORef added <*> readIORef removed

newRrdpStat :: IO RrdpStatWork
newRrdpStat = RrdpStatWork <$> newIORef 0 <*> newIORef 0

addedOne :: RrdpStatWork -> IO ()
addedOne RrdpStatWork {..} = U.increment added

removedOne :: RrdpStatWork -> IO ()
removedOne RrdpStatWork {..} = U.increment removed
