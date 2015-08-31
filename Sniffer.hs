{-# LANGUAGE RecordWildCards #-}

import System.Environment
import Data.Word
import Text.Printf
import Data.List (intercalate)
import Network.Pcap
import Data.Binary
import qualified Data.ByteString.Lazy as B

type EthAddr = (Word8, Word8, Word8, Word8, Word8, Word8)
type IpAddr  = (Word8, Word8, Word8, Word8)

showIpAddr :: IpAddr -> String
showIpAddr (oct1, oct2, oct3, oct4) = intercalate "." [ show oct1, show oct2
                                                      , show oct3, show oct4 ]

data EthHdr = EthHdr { ethdest   :: EthAddr
                     , ethsrc    :: EthAddr
                     , ethlen    :: Word16
                     } deriving (Show, Eq)

data IpHdr = IpHdr { ver_ihl  :: Word8
                   , tos      :: Word8
                   , len      :: Word16
                   , ident    :: Word16
                   , flags_fo :: Word16
                   , ttl      :: Word8
                   , proto    :: Word8
                   , checksum :: Word16
                   , ipsrc    :: IpAddr
                   , ipdest   :: IpAddr
                   } deriving (Show, Eq)

data Packet = Packet { eth :: EthHdr
                     , ip  :: IpHdr
                     } deriving (Eq)

instance Binary EthHdr where
    put EthHdr {..} = do
        put (ethdest :: EthAddr)
        put (ethsrc  :: EthAddr)
        put (ethlen  :: Word16)

    get = do
        ethdest <- get :: Get EthAddr
        ethsrc  <- get :: Get EthAddr
        ethlen  <- get :: Get Word16
        return $ EthHdr ethdest ethsrc ethlen

instance Binary IpHdr where
    put IpHdr {..} = do
        put (ver_ihl  :: Word8)
        put (tos      :: Word8)
        put (len      :: Word16)
        put (ident    :: Word16)
        put (flags_fo :: Word16)
        put (ttl      :: Word8)
        put (proto    :: Word8)
        put (checksum :: Word16)
        put (ipsrc    :: IpAddr)
        put (ipdest   :: IpAddr)

    get = do
        ver_ihl  <- get :: Get Word8
        tos      <- get :: Get Word8
        len      <- get :: Get Word16
        ident    <- get :: Get Word16
        flags_fo <- get :: Get Word16
        ttl      <- get :: Get Word8
        proto    <- get :: Get Word8
        checksum <- get :: Get Word16
        ipsrc    <- get :: Get IpAddr
        ipdest   <- get :: Get IpAddr
        return $ IpHdr ver_ihl tos len ident flags_fo
                       ttl proto checksum ipsrc ipdest

instance Show Packet where
   show Packet {..} = printf ("%-4s       Protocol: %s\n" ++
                              "%-4s      Source IP: %s\n" ++
                              "%-4s Destination IP: %s\n")
                              (" ") (getProto . read . show $ proto ip)
                              (" ") (showIpAddr $ ipdest ip)
                              (" ") (showIpAddr $ ipsrc ip)


main = do
    (device:rest) <- getArgs
    dev <- openLive device 0xFFFF False 0
    loop dev (-1) reader

stripEth :: B.ByteString -> EthHdr
stripEth = decode

stripIp :: B.ByteString -> IpHdr
stripIp = decode

getProto :: Int -> String
getProto 1  = "1 (ICMP)"
getProto 2  = "2 (IGMP)"
getProto 6  = "6 (TCP)"
getProto 17 = "17 (UDP)"
getProto n  = show n ++ " (Protocol Not Handled)"

toPacket :: B.ByteString -> Packet
toPacket dataB = do
    -- Learn to make monads, one could probably be useful here (Packet Monad)?
    let (eth, ethrest)  = B.splitAt 14 dataB
        (ip, protorest) = B.splitAt 20 ethrest
        ethhdr = stripEth eth
        iphdr  = stripIp  ip
    Packet ethhdr iphdr

reader :: Callback
reader dev ptrw8 = do
  (dev, dataB) <- toBS (dev, ptrw8)
  let pkt = toPacket $ B.fromStrict dataB
  putStrLn $ show pkt
