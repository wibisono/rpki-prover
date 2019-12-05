{-# LANGUAGE DeriveAnyClass       #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE RecordWildCards      #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DerivingStrategies #-}

module RPKI.Domain where

import qualified Data.Set as S
import qualified Data.ByteString as B
import qualified Data.Text as T

import Control.DeepSeq
import Codec.Serialise
import Data.Hex (hex)

import Data.Kind (Type)
import Data.Data (Typeable)
import Data.List.NonEmpty
import Data.Hourglass

import GHC.Generics

import qualified Data.X509 as X509

import RPKI.IP    
import RPKI.SignTypes

newtype ASN = ASN Int
    deriving (Show, Eq, Ord, Typeable, Generic, NFData)

data AsResource =  AS !ASN
                 | ASRange  
                    {-# UNPACK #-} !ASN 
                    {-# UNPACK #-} !ASN
    deriving (Show, Eq, Ord, Typeable, Generic, NFData)

data ValidationRFC = Strict_ | Reconsidered
    deriving (Show, Eq, Ord, Typeable, Generic, NFData)

newtype WithRFC (rfc :: ValidationRFC) (r :: ValidationRFC -> Type) = WithRFC (r rfc)
    deriving (Show, Eq, Ord, Typeable, Generic)

type AnRFC r = Either (WithRFC 'Strict_ r) (WithRFC 'Reconsidered r)

withRFC :: AnRFC r -> (forall rfc . r rfc -> a) -> a
withRFC (Left (WithRFC a)) f = f a
withRFC (Right (WithRFC a)) f = f a  

newtype IpResources = IpResources (AnRFC IpResourceSet)    
    deriving (Show, Eq, Ord, Typeable, Generic)

newtype RSet r = RSet (AnRFC (ResourceSet r))
    deriving (Show, Eq, Ord, Typeable, Generic)

data ResourceSet r (rfc :: ValidationRFC) = RS (S.Set r) | Inherit
    deriving (Show, Eq, Ord, Typeable, Generic)

newtype IpResourceSet (rfc :: ValidationRFC) = 
    IpResourceSet (ResourceSet IpResource rfc)
    deriving (Show, Eq, Ord, Typeable, Generic)                    

-- TODO Use library type?
newtype Hash = Hash B.ByteString deriving (Show, Eq, Ord, Typeable, Generic, NFData)

newtype URI  = URI { unURI :: T.Text } deriving (Show, Eq, Ord, Typeable, Generic, NFData)
newtype KI   = KI  B.ByteString deriving (Show, Eq, Ord, Typeable, Generic, NFData)
newtype SKI  = SKI KI deriving (Show, Eq, Ord, Typeable, Generic, NFData)
newtype AKI  = AKI KI deriving (Show, Eq, Ord, Typeable, Generic, NFData)

newtype SessionId = SessionId B.ByteString deriving (Show, Eq, Ord, Typeable, Generic, NFData)
newtype Serial = Serial Integer deriving (Show, Eq, Ord, Typeable, Generic, NFData)
newtype Version = Version Integer deriving (Show, Eq, Ord, Typeable, Generic, NFData)


-- | Objects

newtype CMS a = CMS (SignedObject a) deriving (Show, Eq, Typeable, Generic)

newtype CerObject = CerObject ResourceCert deriving (Show, Eq, Typeable, Generic)
newtype CrlObject = CrlObject SignCRL deriving (Show, Eq, Typeable, Generic)

type MftObject = CMS Manifest
type RoaObject = CMS [Roa]
type GbrObject = CMS Gbr
    
data CrlMeta = CrlMeta {
    locations :: NonEmpty URI, 
    hash      :: Hash, 
    aki       :: AKI    
} deriving (Show, Eq, Ord, Typeable, Generic)

data RpkiMeta = RpkiMeta {
    locations :: NonEmpty URI, 
    hash      :: Hash, 
    aki       :: Maybe AKI, 
    ski       :: SKI, 
    serial    :: Serial
} deriving (Show, Eq, Ord, Typeable, Generic)

data RO = CerRO CerObject 
        | MftRO MftObject
        | RoaRO RoaObject
        | GbrRO GbrObject
    deriving (Show, Eq, Typeable, Generic)

data RpkiObject = RpkiObject RpkiMeta RO 
                | RpkiCrl CrlMeta CrlObject
    deriving (Show, Eq, Typeable, Generic)


data ResourceCertificate (rfc :: ValidationRFC) = ResourceCertificate {
    certX509    :: X509.SignedExact X509.Certificate, 
    ipResources :: Maybe (IpResourceSet rfc), 
    asResources :: Maybe (ResourceSet AsResource rfc)
} deriving (Show, Eq, Typeable, Generic)

newtype ResourceCert = ResourceCert (AnRFC ResourceCertificate)
    deriving (Show, Eq, Typeable, Generic)

data Roa = Roa     
    {-# UNPACK #-} !ASN 
    !APrefix    
    {-# UNPACK #-} !Int
    deriving (Show, Eq, Ord, Typeable, Generic)

data Manifest = Manifest {
    mftNumber   :: Int, 
    fileHashAlg :: X509.HashALG, 
    thisTime    :: DateTime, 
    nextTime    :: DateTime, 
    mftEntries  :: [(T.Text, Hash)]
} deriving (Show, Eq, Typeable, Generic)

data SignCRL = SignCRL {
  crl                :: X509.CRL,
  signatureAlgorithm :: SignatureAlgorithmIdentifier,
  signatureValue     :: SignatureValue,
  encodedValue       :: B.ByteString,
  crlNumber          :: Integer
} deriving (Show, Eq, Typeable, Generic)

data Gbr = Gbr deriving (Show, Eq, Ord, Typeable, Generic)


-- Subject Public Key Info
newtype SPKI = SPKI EncodedBase64
    deriving (Show, Eq, Ord, Typeable, Generic, Serialise)

newtype EncodedBase64 = EncodedBase64 B.ByteString
    deriving (Show, Eq, Ord, Generic, NFData, Serialise)
    deriving newtype (Monoid, Semigroup)
  
newtype DecodedBase64 = DecodedBase64 B.ByteString
    deriving (Show, Eq, Ord, Generic, NFData, Serialise)
    deriving newtype (Monoid, Semigroup)
  

newtype TaName = TaName T.Text
    deriving (Show, Eq, Ord, Generic, NFData, Serialise)

data TA = TA {
    taName        :: TaName
  , taCertificate :: Maybe ResourceCert
  , taUri         :: URI
  , taSpki        :: SPKI
} deriving (Show, Eq, Generic, Serialise)

data RepoType = Rsync | Rrdp

data RsyncRepository = RsyncRepository {
    uri :: URI    
} deriving (Show, Eq, Ord, Typeable, Generic)

data RrdpRepository = RrdpRepository {
    uri :: URI,
    session :: Maybe (SessionId, Serial)
} deriving (Show, Eq, Ord, Typeable, Generic)

data Repository = 
    RsyncRepo RsyncRepository | 
    RrdpRepo RrdpRepository 
    deriving (Show, Eq, Ord, Typeable, Generic)

data Invalid = Error | Warning
    deriving (Show, Eq, Ord, Typeable, Generic)

        

-- serialisation
instance Serialise Hash
instance Serialise RpkiMeta
instance Serialise CrlMeta
instance Serialise URI
instance Serialise AKI
instance Serialise SKI
instance Serialise KI
instance Serialise Serial
instance Serialise RO
instance Serialise Manifest
instance Serialise Roa
instance Serialise Gbr
instance Serialise ASN
instance Serialise a => Serialise (CMS a)
instance Serialise CerObject
instance Serialise CrlObject
instance Serialise SignCRL
instance Serialise ResourceCert
instance Serialise RpkiObject

instance Serialise (WithRFC 'Strict_ ResourceCertificate)
instance Serialise (ResourceCertificate 'Strict_)
instance Serialise (IpResourceSet 'Strict_)
instance Serialise (ResourceSet IpResource 'Strict_)
instance Serialise (ResourceCertificate 'Reconsidered)
instance Serialise (IpResourceSet 'Reconsidered)
instance Serialise (ResourceSet IpResource 'Reconsidered)
instance Serialise (WithRFC 'Reconsidered ResourceCertificate)
instance Serialise (ResourceSet AsResource 'Strict_)
instance Serialise (ResourceSet AsResource 'Reconsidered)
instance Serialise AsResource


-- 
getHash :: RpkiObject -> Hash
getHash (RpkiObject RpkiMeta {..} _) = hash
getHash (RpkiCrl CrlMeta {..} _)     = hash

getLocations :: RpkiObject -> NonEmpty URI
getLocations (RpkiObject RpkiMeta {..} _) = locations
getLocations (RpkiCrl CrlMeta {..} _) = locations

getAKI :: RpkiObject -> Maybe AKI
getAKI (RpkiObject RpkiMeta {..} _) = aki
getAKI (RpkiCrl CrlMeta {..} _) = Just aki

getMeta :: RpkiObject -> RpkiMeta
getMeta (RpkiObject m _) = m

hexHash :: Hash -> String
hexHash (Hash bs) = show $ hex bs

toAKI :: SKI -> AKI
toAKI (SKI ki) = AKI ki

getCMSContent :: CMS a -> a
getCMSContent (CMS so) = cContent $ scEncapContentInfo $ soContent so
