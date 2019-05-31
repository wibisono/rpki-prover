{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ViewPatterns #-}

module RPKI.Cache where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM
import Control.Monad
import Control.Exception
  
import qualified Data.Text as T
import qualified Data.ByteString as B
import qualified Data.Map as M
import Data.Maybe (maybe)

import Data.Hashable
import qualified StmContainers.Map as SM

import RPKI.Domain

data Store = Store

load :: RpkiObject r => Store -> AKI -> IO [r]
load store aki = pure []

-- load :: (Eq k, Hashable k) =>
--         Cache k v -> k -> (k -> IO (Maybe v)) -> IO (Maybe v)
-- load (Cache cache) k loadIO = do
--     atomically zzz >>= \case 
--       DoIO io -> io
--       DoSTM s -> pure s
--     where
--       zzz = do
--         v <- SM.lookup k cache 
--         case v of        
--           Just Loading   -> retry
--           Just (Value v) -> pure $ DoSTM $ Just v
--           Nothing -> do
--             SM.insert Loading k cache
--             pure $ DoIO $ try (loadIO k) >>= \case 
--               Left e         -> throw e
--               Right Nothing  -> pure Nothing
--               Right (Just v) -> do 
--                 atomically (SM.insert (Value v) k cache)
--                 pure $ Just v      
          

