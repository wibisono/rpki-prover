{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE QuasiQuotes      #-}
{-# LANGUAGE RecordWildCards  #-}

module RPKI.Rsync where

import           Data.Bifunctor

import           Control.Concurrent.Async
import           Control.Monad
import           Control.Monad.Reader
import           Control.Monad.Trans.Except
import           UnliftIO.Exception                    hiding (fromEither)

import qualified Data.ByteString                       as B
import           Data.String.Interpolate
import qualified Data.Text                             as T
import           Data.IORef

import           RPKI.AppMonad
import           RPKI.Config
import           RPKI.Domain
import           RPKI.Errors
import           RPKI.Logging
import           RPKI.Parse.Parse
import           RPKI.Store.Base.Storage
import           RPKI.Store.Base.Storable
import           RPKI.Store.Stores
import qualified RPKI.Util                             as U

import           Data.Has

import qualified Control.Concurrent.Chan.Unagi.Bounded as Chan

import           System.Directory                      (createDirectoryIfMissing,
                                                        doesDirectoryExist,
                                                        getDirectoryContents)
import           System.FilePath                       ((</>))

import           System.Exit
import           System.Process.Typed


newtype RsyncConf = RsyncConf {
  rsyncRoot :: FilePath
}

-- | Download one file using rsync
rsyncFile :: (Has RsyncConf conf, Has AppLogger conf) => 
              URI -> 
              (B.ByteString -> PureValidator conf B.ByteString) ->
              ValidatorT conf IO RpkiObject
rsyncFile (URI uri) validateBinary = do
  RsyncConf {..} <- asks getter
  let destination = rsyncDestination rsyncRoot uri
  let rsync = rsyncProcess (URI uri) destination RsyncOneFile
  logger :: AppLogger        <- asks getter 
  (exitCode, stdout, stderr) <- lift3 $ readProcess rsync      
  case exitCode of  
    ExitFailure errorCode -> do
      lift3 $ logError_ logger [i|Rsync process failed: #rsync 
                                  with code #errorCode, 
                                  stderr = #stderr, 
                                  stdout = #stdout|]        
      lift $ throwE $ RsyncE $ RsyncProcessError errorCode stderr  
    ExitSuccess -> do
        bs        <- fromTry (RsyncE . FileReadError . U.fmtEx) $ B.readFile destination
        checkedBs <- pureToValidatorT $ validateBinary bs
        fromEither $ first ParseE $ readObject (U.convert uri) checkedBs


-- | Process the whole rsync repository, download it, traverse the directory and 
-- | add all the relevant objects to the storage.
processRsync :: (Has RsyncConf conf, Has AppLogger conf, Has Config conf, Storage s) => 
                RsyncRepository -> 
                RpkiObjectStore s -> 
                ValidatorT conf IO ()
processRsync (RsyncRepository (URI uri)) objectStore = do 
  RsyncConf {..} <- asks getter
  let destination = rsyncDestination rsyncRoot uri
  let rsync = rsyncProcess (URI uri) destination RsyncDirectory

  _ <- fromTry (RsyncE . FileReadError . U.fmtEx) $ 
    createDirectoryIfMissing True destination
  
  logger :: AppLogger   <- asks getter 
  lift3 $ logInfo_ logger [i|Going to run #{rsync}|]
  (exitCode, stdout, stderr) <- lift $ readProcess rsync
  lift3 $ logInfo_ logger [i|Finished rsynching #{destination}|]
  case exitCode of  
    ExitSuccess -> do
      config :: Config <- asks getter
      count <- fromIOEither $ loadRsyncRepository logger config rsyncRoot objectStore      
      lift3 $ logInfo_ logger [i|Finished loading #{count} objects into local storage|]      
    ExitFailure errorCode -> do
      lift3 $ logError_ logger [i|Rsync process failed: #{rsync} 
                                  with code #{errorCode}, 
                                  stderr = #{stderr}, 
                                  stdout = #{stdout}|]
      lift $ throwE $ RsyncE $ RsyncProcessError errorCode stderr  
  

-- | Recursively traverse given directory and save all the parseable 
-- | objects into the storage.
loadRsyncRepository :: (Storage s, Logger logger) => 
                        logger ->
                        Config ->
                        FilePath -> 
                        RpkiObjectStore s -> 
                        IO (Either SomeError Integer)
loadRsyncRepository logger config topPath objectStore = do
    counter <- newIORef 0
    (chanIn, chanOut) <- Chan.newChan $ parallelism config
    (r1, r2) <- concurrently (travelrseFS chanIn) (saveObjects counter chanOut)
    c <- readIORef counter
    pure (first RsyncE r1 >> first StorageE r2 >> pure c)
  where 
    travelrseFS chanIn = 
      first (FileReadError . U.fmtEx) <$> try (
          readFiles chanIn topPath 
            `finally` 
            Chan.writeChan chanIn Nothing)        

    readFiles chanIn currentPath = do
      names <- getDirectoryContents currentPath
      let properNames = filter (`notElem` [".", ".."]) names
      forM_ properNames $ \name -> do
        let path = currentPath </> name
        doesDirectoryExist path >>= \case
          True  -> readFiles chanIn path
          False -> 
            when (supportedExtension path) $ do
              a <- async $ do 
                bs <- B.readFile path                
                pure $! case first ParseE $ readObject path bs of
                  Left e   -> SError e
                  -- "toStorableObject ro" has to happen in this thread, as it is the way to 
                  -- force computation of the serialised object and gain some parallelism
                  Right ro -> SObject $ toStorableObject ro
                  
              Chan.writeChan chanIn $ Just a      

    saveObjects counter chanOut = 
      first (StorageError . U.fmtEx) <$> 
        try (rwTx objectStore go)
      where 
        go tx = 
          Chan.readChan chanOut >>= \case 
            Nothing -> pure ()
            Just a  -> try (wait a) >>= process tx >> go tx

        process tx = \case
          Left (e :: SomeException) -> 
            logError_ logger [i|An error reading the object: #{e}|]
          Right (SError e) -> 
            logError_ logger [i|An error parsing or serialising the object: #{e}|]
          Right (SObject so@(StorableObject ro _)) -> do
            let h = getHash ro
            getByHash tx objectStore h >>= \case 
                Nothing -> do
                  putObject tx objectStore h so
                  void $ atomicModifyIORef counter (\c -> (c + 1, ()))
                Just _  ->
                    -- TODO Add location
                    logInfo_ logger [i|There's an existing object with hash: #{hexHash h}, ignoring the new one.|]
              

data RsyncCL = RsyncOneFile | RsyncDirectory

rsyncProcess :: URI -> FilePath -> RsyncCL -> ProcessConfig () () ()
rsyncProcess (URI uri) destination rsyncCL = 
  let extraOptions = case rsyncCL of 
        RsyncOneFile   -> []
        RsyncDirectory -> ["--recursive", "--delete", "--copy-links" ]
      options = [ "--timeout=300",  "--update",  "--times" ] ++ extraOptions
      in proc "rsync" $ options ++ [ T.unpack uri, destination ]

-- TODO Make it generate shorter filenames
rsyncDestination :: FilePath -> T.Text -> FilePath
rsyncDestination root uri = root </> T.unpack (U.normalizeUri uri)


              
