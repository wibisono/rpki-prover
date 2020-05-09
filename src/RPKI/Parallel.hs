module RPKI.Parallel where

import Numeric.Natural
import Control.Monad
import Control.Concurrent.STM

import qualified Control.Concurrent.STM.TBQueue as Q

import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Exception.Lifted

import Control.Monad.Trans.Control
import Control.Concurrent.Async.Lifted as AsyncL


data Parallelism = Dynamic !(TVar Natural) Natural | Fixed Natural

dynamicPara :: Natural -> STM Parallelism
dynamicPara n = do 
    c <- newTVar 0
    pure $ Dynamic c n

dynamicParaIO :: Natural -> IO Parallelism
dynamicParaIO = atomically . dynamicPara    

fixedPara :: Natural -> Parallelism
fixedPara = Fixed

atLeastOneThread :: Natural -> Natural
atLeastOneThread n = if n < 2 then 1 else n - 1

parallel :: (Traversable t, MonadBaseControl IO m, MonadIO m) =>
            Parallelism -> t a -> (a -> m b) -> m (t b)
parallel parallelism as f =
    case parallelism of 
        Fixed n                     -> doFixed n
        Dynamic currentPara maxPara -> doDynamic currentPara maxPara
    where 
        doFixed para =
            snd <$> bracketChan (atLeastOneThread para) writeAll readAll AsyncL.cancel
            where
                writeAll queue = forM_ as $ \a -> do
                    aa <- AsyncL.async $ f a
                    liftIO $ atomically $ Q.writeTBQueue queue aa
                readAll queue = forM as $ \_ ->         
                    AsyncL.wait =<< (liftIO . atomically $ Q.readTBQueue queue)    

        doDynamic currentPara maxPara =
            snd <$> bracketChan (atLeastOneThread maxPara) writeAll readAll cancelIt
            where
                cancelIt aa = do 
                    liftIO $ atomically $ modifyTVar' currentPara decN
                    AsyncL.cancel aa

                writeAll queue = forM_ as $ \a -> 
                    join $ liftIO $ atomically $ do 
                        c <- readTVar currentPara
                        if c >= maxPara
                            then retry
                            else 
                                -- TODO lock?
                                pure $ do 
                                aa <- AsyncL.async $ f a
                                liftIO $ atomically $ do 
                                    -- TODO unlock?
                                    Q.writeTBQueue queue aa
                                    modifyTVar' currentPara incN

                readAll queue = forM as $ \_ -> do
                    aa <- liftIO $ atomically $ do                         
                        modifyTVar' currentPara decN
                        Q.readTBQueue queue
                    AsyncL.wait aa

        incN, decN :: Natural -> Natural
        incN c = c + 1
        decN c = if c <= 1 then 1 else c - 1


-- | Utility function for a specific case of producer-consumer pair 
-- where consumer works within a transaction (represented as withTx function)
--  
txConsumeFold :: (Traversable t, MonadBaseControl IO m, MonadIO m) =>
            Natural ->
            t a ->                      -- ^ traversed collection
            (a -> m q) ->               -- ^ producer, called for every item of the traversed argument
            ((tx -> m r) -> m r) ->     -- ^ transaction in which all consumerers are wrapped
            (tx -> q -> r -> m r) ->    -- ^ producer, called for every item of the traversed argument
            r ->                        -- ^ fold initial value
            m r
txConsumeFold poolSize as produce withTx consume accum0 =
    snd <$> bracketChan 
                (atLeastOneThread poolSize)
                writeAll 
                readAll 
                (const $ pure ())
    where
        writeAll queue = forM_ as $
            liftIO . atomically . Q.writeTBQueue queue <=< produce
        readAll queue = withTx $ \tx -> foldM (f tx) accum0 as 
            where
                f tx accum _ = do
                    a <- liftIO $ atomically $ Q.readTBQueue queue
                    consume tx a accum        


bracketChan :: (MonadBaseControl IO m, MonadIO m) =>
                Natural ->
                (Q.TBQueue t -> m b) ->
                (Q.TBQueue t -> m c) ->
                (t -> m w) ->
                m (b, c)
bracketChan size produce consume kill = do
    queue <- liftIO $ atomically $ Q.newTBQueue size
    (AsyncL.concurrently (produce queue) (consume queue))
        `finally`
        (killAll queue)
    where
        killAll queue = do
            a <- liftIO $ atomically $ Q.tryReadTBQueue queue
            case a of   
                Nothing -> pure ()
                Just as -> kill as >> killAll queue
