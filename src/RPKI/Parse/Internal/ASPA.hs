{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}

module RPKI.Parse.Internal.ASPA where

import qualified Data.ByteString as BS  

import Control.Monad
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Parse
import Data.ASN1.BitArray

import Data.Bifunctor
import Data.String.Interpolate.IsString

import RPKI.Domain 
import RPKI.Resources.Types
import RPKI.Parse.Internal.Common
import RPKI.Parse.Internal.SignedObject 

-- | Parse ASPA, https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-profile
--
parseAspa :: BS.ByteString -> ParseResult AspaObject
parseAspa bs = do
    asns      <- first (fmtErr . show) $ decodeASN1' BER bs  
    signedAspa <- first fmtErr $ runParseASN1 (parseSignedObject $ parseSignedContent parseAspas') asns
    hash' <- getMetaFromSigned signedAspa bs
    pure $ newCMSObject hash' (CMS signedAspa)
    where     
        parseAspas' = onNextContainer Sequence $ do
            -- TODO Fix it so that it would work with present attestation version
            asId <- getInteger (pure . fromInteger) "Wrong ASID"
            mconcat <$> onNextContainer Sequence (getMany $
                onNextContainer Sequence $ 
                getAddressFamily "Expected an address family here" >>= \case 
                    Right Ipv4F -> getAspa asId Ipv4F
                    Right Ipv6F -> getAspa asId Ipv6F
                    Left af     -> throwParseError $ "Unsupported address family: " ++ show af)

        getAspa :: Int -> AddrFamily -> ParseASN1 [Vrp]
        getAspa asId addressFamily = onNextContainer Sequence $ getMany $
            getNextContainerMaybe Sequence >>= \case       
                Just [BitString (BitArray nzBits bs')] ->
                    makeVrp asId bs' nzBits nzBits addressFamily
                Just [BitString (BitArray nzBits bs'), IntVal maxLength] ->
                    makeVrp asId bs' nzBits maxLength addressFamily
                Just a  -> throwParseError [i|Unexpected ASPA content: #{a}|]
                Nothing -> throwParseError "Unexpected ASPA content"

        makeVrp asId bs' nonZeroBitCount prefixMaxLength addressFamily = do
            when (nonZeroBitCount > fromIntegral prefixMaxLength) $
                throwParseError [i|Actual prefix length #{nonZeroBitCount} is bigger than the maximum length #{prefixMaxLength}.|]

            case addressFamily of
                Ipv4F 
                    | prefixMaxLength <= 0  -> 
                        throwParseError [i|Negative or zero value for IPv4 prefix max length: #{prefixMaxLength}|]
                    | prefixMaxLength > 32 -> 
                        throwParseError [i|Too big value for IPv4 prefix max length: #{prefixMaxLength}|]
                    | otherwise ->
                        pure $ mkVrp nonZeroBitCount prefixMaxLength Ipv4P
                Ipv6F 
                    | prefixMaxLength <= 0  -> 
                        throwParseError [i|Negative or zero value for IPv6 prefix max length: #{prefixMaxLength}|]
                    | prefixMaxLength > 128 -> 
                        throwParseError [i|Too big value for IPv6 prefix max length: #{prefixMaxLength}|]
                    | otherwise ->
                        pure $ mkVrp nonZeroBitCount prefixMaxLength Ipv6P
            where 
                mkVrp :: (Integral a, Integral c, Prefix b) => a -> c -> (b -> IpPrefix) -> Vrp
                mkVrp nz len mkIp = Vrp 
                            (ASN (fromIntegral asId)) 
                            (mkIp $ make bs' (fromIntegral nz)) 
                            (PrefixLength $ fromIntegral len)