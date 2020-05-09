{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module RPKI.Parse.Internal.CRL where
    
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Parse
import           Data.ASN1.Types
import           Data.Bifunctor             (first)
import qualified Data.ByteString            as BS

import qualified Data.List                  as List
import qualified Data.Set                   as Set

import           Data.X509

import           RPKI.Domain
import           RPKI.Parse.Internal.Common
import qualified RPKI.Util                  as U


parseCrl :: BS.ByteString -> ParseResult (URI -> CrlObject)
parseCrl bs = do
    asns                <- first (fmtErr . show) $ decodeASN1' BER bs
    (x509crl, signCrlF) <- first fmtErr $ runParseASN1 getCrl asns  
    exts <- case crlExtensions x509crl of
                Extensions Nothing           -> Left $ fmtErr "No CRL extensions"
                Extensions (Just extensions) -> Right extensions
    akiBS <- case extVal exts id_authorityKeyId of
                Nothing -> Left $ fmtErr "No AKI in CRL"
                Just a  -> Right a

    aki' <- case decodeASN1' BER akiBS of
                Left e -> Left $ fmtErr $ "Unknown AKI format: " <> show e
                Right [Start Sequence, Other Context 0 ki, End Sequence] -> Right ki
                Right s -> Left $ fmtErr $ "Unknown AKI format: " <> show s
    
    crlNumberBS :: BS.ByteString  <- case extVal exts id_crlNumber of
                Nothing -> Left $ fmtErr "No CRL number in CRL"
                Just n  -> Right n

    numberAsns <- first (fmtErr . show) $ decodeASN1' BER crlNumberBS
    crlNumber' <- first fmtErr $ runParseASN1 (getInteger pure "Wrong CRL number") numberAsns

    pure $ \location -> makeCrl 
        location 
        (AKI $ KI aki') 
        (U.sha256s bs) 
        (signCrlF crlNumber' )        
    where          
        getCrl = onNextContainer Sequence $ do
            (asns, crl') <- getNextContainerMaybe Sequence >>= \case 
                Nothing   -> throwParseError "Invalid CRL format"
                Just asns -> 
                    case runParseASN1 getCrlContent asns of
                        Left e  -> throwParseError $ "Invalid CRL format: " <> e
                        Right c -> pure (asns, c)
            signatureId  <- getObject
            signatureVal <- parseSignature
            let encoded = encodeASN1' DER $ [Start Sequence] <> asns <> [End Sequence]

            let revokedSerials = Set.fromList $ List.sort $ 
                    map (\RevokedCertificate {..} -> Serial revokedSerialNumber) $ crlRevokedCertificates crl'

            let mkSignCRL crlNumber' = SignCRL crl' 
                        (SignatureAlgorithmIdentifier signatureId) 
                        signatureVal encoded crlNumber' revokedSerials
            pure (crl', mkSignCRL)                
        
        getCrlContent = do        
            x509Crl    <- parseX509CRL
            extensions <- onNextContainer (Container Context 0) $ 
                            onNextContainer Sequence $ getMany getObject 
            pure $ x509Crl { crlExtensions = Extensions (Just extensions) }

        -- This is copy-pasted from the Data.X509.CRL to fix getRevokedCertificates 
        -- which should be more flexible.
        parseX509CRL = 
            CRL <$> (getNext >>= getVersion)
                <*> getObject
                <*> getObject
                <*> (getNext >>= getThisUpdate)
                <*> getNextUpdate
                <*> getRevokedCertificates
                <*> getObject
            where 
                getVersion (IntVal v) = pure $ fromIntegral v
                getVersion _          = throwParseError "Unexpected type for version"

                getThisUpdate (ASN1Time _ t _) = pure t
                getThisUpdate t                = throwParseError $ "Bad this update format, expecting time" <> show t

                getNextUpdate = getNextMaybe $ \case 
                    (ASN1Time _ tnext _) -> Just tnext
                    _                    -> Nothing

                getRevokedCertificates = 
                    onNextContainerMaybe Sequence (getMany getObject) >>= \case
                        Nothing -> pure []
                        Just rc -> pure rc




