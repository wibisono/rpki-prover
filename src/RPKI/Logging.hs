{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DerivingStrategies #-}

module RPKI.Logging where

import Codec.Serialise
import Colog

import Data.Text (Text)

import Control.Monad (when)
import Control.Monad.IO.Class

import GHC.Generics (Generic)

import GHC.Stack (callStack)
import System.IO (BufferMode (..), Handle, hSetBuffering, stdout, stderr)


class Logger logger where
    logError_ :: logger -> Text -> IO ()
    logWarn_  :: logger -> Text -> IO ()
    logInfo_  :: logger -> Text -> IO ()
    logDebug_ :: logger -> Text -> IO ()

data LogLevel = ErrorL | WarnL | InfoL | DebugL
    deriving stock (Show, Eq, Ord, Generic)
    deriving anyclass (Serialise)

data AppLogger = AppLogger {
        logLevel :: LogLevel,
        logAction :: LogAction IO Message
    }


instance Logger AppLogger where
    logError_ AppLogger {..} = logWhat E logAction

    logWarn_  AppLogger {..} s = 
        when (logLevel >= WarnL) $ logWhat W logAction s        

    logInfo_  AppLogger {..} s = 
        when (logLevel >= InfoL) $ logWhat I logAction s

    logDebug_ AppLogger {..} s = 
        when (logLevel >= DebugL) $ logWhat D logAction s        

defaultsLogLevel :: LogLevel
defaultsLogLevel = InfoL

logWhat :: Severity -> LogAction IO Message -> Text -> IO ()
logWhat sev la textMessage = la <& Msg sev callStack textMessage    

logErrorM, logWarnM, logInfoM, logDebugM :: (Logger logger, MonadIO m) => 
                                            logger -> Text -> m ()
logErrorM logger t = liftIO $ logError_ logger t
logWarnM logger t  = liftIO $ logWarn_ logger t
logInfoM logger t  = liftIO $ logInfo_ logger t
logDebugM logger t = liftIO $ logDebug_ logger t


withMainAppLogger :: LogLevel -> (AppLogger -> LoggerT Text IO a) -> IO a
withMainAppLogger logLevel f = withLogger logLevel (stdout, logTextStdout) f  

withWorkerLogger :: LogLevel -> (AppLogger -> LoggerT Text IO a) -> IO a
withWorkerLogger logLevel f = withLogger logLevel (stderr, logTextStderr) f  

withLogger :: LogLevel -> (Handle, LogAction IO Text) -> (AppLogger -> LoggerT Text IO a) -> IO a
withLogger logLevel (stream, streamLogger) f = do     
    hSetBuffering stream LineBuffering
    withBackgroundLogger
        defCapacity
        streamLogger
        (\logg -> usingLoggerT logg $ f $ AppLogger logLevel (fullMessageAction logg))
  where
    fullMessageAction logg = upgradeMessageAction defaultFieldMap $ 
        cmapM (\msg -> fmtRichMessageCustomDefault msg formatRichMessage) logg    
        
    formatRichMessage _ (maybe "" showTime -> time) Msg{..} =
        showSeverity msgSeverity
        <> time            
        <> msgText           