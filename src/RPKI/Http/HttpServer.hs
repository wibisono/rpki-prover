{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedLabels  #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE TemplateHaskell #-}

module RPKI.Http.HttpServer where

import           Control.Lens                     ((^.))

import           Control.Concurrent.STM
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Maybe
import           Control.Monad.Error.Class

import           FileEmbedLzma

import           Servant hiding (URI)
import           Servant.Server.Generic

import qualified Data.ByteString.Builder          as BS

import qualified Data.List.NonEmpty               as NonEmpty
import           Data.Maybe                       (maybeToList)
import qualified Data.Set                         as Set
import qualified Data.Map.Monoidal.Strict         as MonoidalMap
import           Data.Text                       (Text)

import           RPKI.AppContext
import           RPKI.Config
import           RPKI.AppTypes
import           RPKI.AppState
import           RPKI.Domain
import           RPKI.Http.Messages
import           RPKI.Metrics.Prometheus
import           RPKI.Reporting
import           RPKI.Http.Api
import           RPKI.Http.Types
import           RPKI.Http.UI
import           RPKI.Store.Base.Storage
import           RPKI.Store.Database
import           RPKI.Resources.Types
import           RPKI.Store.Types
import           RPKI.SLURM.Types
import           RPKI.Util


httpApi :: Storage s => AppContext s -> Application
httpApi appContext@AppContext {..} = genericServe HttpApi {
        api     = apiServer,
        metrics = convert <$> textualMetrics,        
        ui      = uiServer,
        staticContent = serveDirectoryEmbedded $(embedRecursiveDir "static")
    }
  where
    apiServer = genericServer API {
        vrpsJson = liftIO (getVRPValidated appContext),
        vrpsCsv = liftIO (getVRPValidatedRaw appContext),

        vrpsCsvFiltered  = liftIO (getVRPSlurmedRaw appContext),
        vrpsJsonFiltered = liftIO (getVRPSlurmed appContext),

        slurm = getSlurm appContext,
                
        fullValidationResults    = getValidationsDto appContext,
        validationResultsMinimal = toMinimalValidations <$> getValidationsDto appContext,
        metrics = snd <$> getMetrics appContext,                
        publicationsPoints = getPPs appContext,
        lmdbStats = getStats appContext,
        objectView = getRpkiObject appContext,
        config = pure config
    }

    uiServer = do 
        worldVersion <- liftIO $ getLastVersion appContext
        vResults     <- liftIO $ getValidations appContext
        metrics <- getMetrics appContext
        pure $ mainPage worldVersion vResults metrics    


getVRPValidated :: Storage s => AppContext s -> IO [VrpDto]
getVRPValidated appContext = getVRPs appContext (readTVar . (^. #validatedVrps))

getVRPSlurmed :: Storage s => AppContext s -> IO [VrpDto]
getVRPSlurmed appContext = getVRPs appContext (readTVar . (^. #filteredVrps))         

getVRPValidatedRaw :: Storage s => AppContext s -> IO RawCVS
getVRPValidatedRaw appContext = 
    rawCSV <$> getVRPs appContext (readTVar . (^. #validatedVrps))    

getVRPSlurmedRaw :: Storage s => AppContext s -> IO RawCVS
getVRPSlurmedRaw appContext =
    rawCSV <$> getVRPs appContext (readTVar . (^. #filteredVrps))


getVRPs :: Storage s => AppContext s -> (AppState -> STM Vrps) -> IO [VrpDto] 
getVRPs AppContext {..} func = do 
    z <- do 
        vrps <- atomically (func appState)
        if vrps == mempty
            then                  
                getLatestVRPs =<< readTVarIO database                
            else 
                pure $ Just vrps
    pure $ case z of 
        Nothing   -> []
        Just vrps -> [ VrpDto a p len (unTaName ta) | 
                            (ta, vrpSet) <- MonoidalMap.toList $ unVrps vrps,
                            Vrp a p len  <- Set.toList vrpSet ]       


getValidations :: Storage s => AppContext s -> IO (Maybe (ValidationsDto FullVDto))
getValidations AppContext {..} = do 
    db@DB {..} <- readTVarIO database 
    roTx versionStore $ \tx -> 
        runMaybeT $ do
            lastVersion <- MaybeT $ getLastCompletedVersion db tx
            validations <- MaybeT $ validationsForVersion tx validationsStore lastVersion
            let validationDtos = map toVR $ validationsToList validations
            pure $ ValidationsDto {
                    version   = lastVersion,
                    timestamp = versionToMoment lastVersion,
                    validations = validationDtos
                }

getValidationsDto :: (MonadIO m, Storage s, MonadError ServerError m) => 
                    AppContext s -> m (ValidationsDto FullVDto)
getValidationsDto appContext = do
    vs <- liftIO $ getValidations appContext         
    maybe notFoundException pure vs    

getLastVersion :: Storage s => AppContext s -> IO (Maybe WorldVersion)
getLastVersion AppContext {..} = do 
    db <- readTVarIO database 
    roTx db $ getLastCompletedVersion db              
        
getMetrics :: (MonadIO m, Storage s, MonadError ServerError m) => 
            AppContext s -> m (RawMetric, MetricsDto)
getMetrics AppContext {..} = do
    db@DB {..} <- liftIO $ readTVarIO database 
    metrics <- liftIO $ roTx db $ \tx ->
        runMaybeT $ do
            lastVersion <- MaybeT $ getLastCompletedVersion db tx
            rawMetrics  <- MaybeT $ metricsForVersion tx metricStore lastVersion
            pure (rawMetrics, toMetricsDto rawMetrics)
    maybe notFoundException pure metrics


notFoundException :: MonadError ServerError m => m a
notFoundException = throwError err404 { errBody = "Working, please hold still!" }

getSlurm :: (MonadIO m, Storage s, MonadError ServerError m) => 
            AppContext s -> m Slurm
getSlurm AppContext {..} = do
    db <- liftIO $ readTVarIO database 
    z  <- liftIO $ roTx db $ \tx ->
        runMaybeT $ do
                lastVersion <- MaybeT $ getLastCompletedVersion db tx
                MaybeT $ slurmForVersion tx db lastVersion                        
    case z of 
        Nothing -> throwError err404 { errBody = "No SLURM for this version" }
        Just m  -> pure m
    
toVR :: (Scope a, Set.Set VIssue) -> FullVDto
toVR (Scope scope, issues) = FullVDto {
        issues = map toDto $ Set.toList issues,
        path   = map focusToText $ NonEmpty.toList scope,
        url    = focusToText $ NonEmpty.head scope
    }
  where
    toDto = \case
        VErr e               -> ErrorDto $ toMessage e
        (VWarn (VWarning w)) -> WarningDto $ toMessage w
    

getStats :: (MonadIO m, Storage s) => AppContext s -> m TotalDBStats
getStats AppContext {..} = liftIO $ getTotalDbStats =<< readTVarIO database             

getPPs :: (MonadIO m, Storage s) => AppContext s -> m PublicationPointDto
getPPs AppContext {..} = liftIO $ do 
    db <- readTVarIO database             
    pps <- roTx db $ \tx -> getPublicationPoints tx db
    pure $ toPublicationPointDto pps

getRpkiObject :: (MonadIO m, Storage s, MonadError ServerError m) 
                => AppContext s 
                -> Maybe Text 
                -> Maybe Text 
                -> m [RObject]
getRpkiObject AppContext {..} uri hash =
    case (uri, hash) of 
        (Nothing,  Nothing) -> 
            throwError $ err400 { errBody = "'uri' or 'hash' must be provided." }

        (Just u, Nothing) -> do 
            case parseRpkiURL u of 
                Left _ -> 
                    throwError $ err400 { errBody = "'uri' is not a valid object URL." }

                Right rpkiUrl -> liftIO $ do 
                    DB {..} <- readTVarIO database 
                    roTx objectStore $ \tx -> 
                        (RObject <$>) <$> getByUri tx objectStore rpkiUrl

        (Nothing, Just hash') -> 
            case parseHash hash' of 
                Left _  -> throwError err400 
                Right h -> liftIO $ do 
                    DB {..} <- readTVarIO database 
                    roTx objectStore $ \tx -> 
                        (RObject <$>) . maybeToList <$> getByHash tx objectStore h                                      

        (Just _, Just _) -> 
            throwError $ err400 { errBody = 
                "Only 'uri' or 'hash' must be provided, not both." }


rawCSV :: [VrpDto] -> RawCVS
rawCSV vrpDtos = 
    RawCVS $ BS.toLazyByteString $ header <> body
  where
    header = str "ASN,IP Prefix,Max Length,Trust Anchor\n"    
    body = mconcat $ map toBS vrpDtos

    toBS VrpDto {
            asn = ASN as, 
            maxLength = PrefixLength ml,
            ..
        } = str "AS" <> str (show as) <> ch ',' <> 
            str (prefixStr prefix) <> ch ',' <> 
            str (show ml) <> ch ',' <> 
            str (convert ta) <> ch '\n'
    
    prefixStr (Ipv4P (Ipv4Prefix p)) = show p
    prefixStr (Ipv6P (Ipv6Prefix p)) = show p

    str = BS.stringUtf8
    ch  = BS.charUtf8    