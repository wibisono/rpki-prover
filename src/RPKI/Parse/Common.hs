{-# LANGUAGE OverloadedStrings #-}

module RPKI.Parse.Common where
  
import Data.Bifunctor

import qualified Data.ByteString as B  
import qualified Data.Text as T  

import Data.Char (chr)

import Data.ASN1.OID
import Data.ASN1.Types
import Data.ASN1.Parse
import Data.ASN1.BitArray

import RPKI.IP

newtype ParseError s = ParseError s
  deriving (Eq, Show, Functor)

type ParseResult a = Either (ParseError T.Text) a


oid_pkix, oid_pe :: OID
id_pe_ipAddrBlocks, id_pe_autonomousSysIds :: OID
id_pe_ipAddrBlocks_v2, id_pe_autonomousSysIds_v2 :: OID

oid_pkix = [1, 3, 6, 1, 5, 5, 7]
oid_pe                    = oid_pkix ++ [ 1 ]
id_pe_ipAddrBlocks        = oid_pe ++ [ 7 ]
id_pe_autonomousSysIds    = oid_pe ++ [ 8 ]
id_pe_ipAddrBlocks_v2     = oid_pe ++ [ 28 ]
id_pe_autonomousSysIds_v2 = oid_pe ++ [ 29 ]  

id_subjectKeyId, id_authorityKeyId :: OID
id_subjectKeyId   = [2, 5, 29, 14]
id_authorityKeyId = [2, 5, 29, 35]

id_pkcs9, id_contentType, id_messageDigest, id_signingTime, id_binarySigningTime :: OID
id_pkcs9              = [1, 2, 840, 113549, 1, 9]
id_contentType        = id_pkcs9 ++ [3]
id_messageDigest      = id_pkcs9 ++ [4]
id_signingTime        = id_pkcs9 ++ [5]
id_binarySigningTime  = id_pkcs9 ++ [16, 2, 46]

fmtErr :: String -> ParseError T.Text
fmtErr = ParseError . T.pack

mapParseErr :: Either String a -> ParseResult a       
mapParseErr = first fmtErr

parseError :: String -> ASN1 -> ParseASN1 a
parseError m a = throwParseError $ case m of 
      [] -> show a
      m' -> m' ++ "(" ++ show a ++ ")"

getNull_ :: ParseASN1 a -> ParseASN1 a
getNull_ f = getNull f ""

getNull :: ParseASN1 a -> String -> ParseASN1 a
getNull f m = getNext >>= \case 
      Null -> f
      a    -> parseError m a

getInteger :: (Integer -> ParseASN1 a) -> String -> ParseASN1 a
getInteger f m = getNext >>= \case 
      IntVal i -> f i
      b        -> throwParseError $ m ++ "(" ++ show b ++ ")"

getOID :: (OID -> ParseASN1 a) -> String -> ParseASN1 a
getOID f m = getNext >>= \case 
      OID oid -> f oid
      a       -> parseError m a

getIA5String :: (String -> ParseASN1 a) -> String -> ParseASN1 a
getIA5String f m = getNext >>= \case 
      ASN1String (ASN1CharacterString IA5 bs) -> f $ map (chr .fromEnum) $ B.unpack bs
      a                                       -> parseError m a

getBitString :: (B.ByteString -> ParseASN1 a) -> String -> ParseASN1 a
getBitString f m = getNext >>= \case 
      BitString (BitArray _ bs) -> f bs
      a                         -> parseError m a

getAddressFamily :: String -> ParseASN1 (Either B.ByteString AddrFamily)
getAddressFamily m = getNext >>= \case 
  (OctetString familyType) -> 
    case familyType of 
      "\NUL\SOH" -> pure $ Right Ipv4F
      "\NUL\STX" -> pure $ Right Ipv6F
      af         -> pure $ Left af 
  a              -> parseError m a      
  
