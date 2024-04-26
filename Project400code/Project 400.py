# Project 400
# James McDaid S00200889
###IMPORTS
import base64
import falconPy.falcon
import kyberPy
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import falconPy
import kyberPy.kyber
import time
import dilithiumPy
import dilithiumPy.dilithium
from sphincsPy.package.sphincs import Sphincs

###Kyber###
print("kyber")
####512####
print("512")
#####Keygen#####
print("Keygen")
#start timer
startime = time.perf_counter()
#excute
pk, sk = kyberPy.kyber.Kyber512.keygen()
#stop
endtime = time.perf_counter()
#record
timeKyber512KeyGen = endtime-startime
print(timeKyber512KeyGen)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
c, key = kyberPy.kyber.Kyber512.enc(pk)
#stop
endtime = time.perf_counter()
#record
timeKyber512Enc = endtime-startime
print(timeKyber512Enc)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
_key = kyberPy.kyber.Kyber512.dec(c, sk)
#stop
endtime = time.perf_counter()
#record
timeKyber512KeyDec = endtime-startime
print(timeKyber512KeyDec)

####Kyber768####
print("768")
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
pk, sk = kyberPy.kyber.Kyber768.keygen()
#stop
endtime = time.perf_counter()
#record
timeKyber768KeyGen = endtime-startime
print(timeKyber768KeyGen)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
c, key = kyberPy.kyber.Kyber768.enc(pk)
#stop
endtime = time.perf_counter()
#record
timeKyber768Enc = endtime-startime
print(timeKyber768Enc)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
_key = kyberPy.kyber.Kyber768.dec(c, sk)
#stop
endtime = time.perf_counter()
#record
timeKyber768Dec = endtime-startime
print(timeKyber768Dec)
####Kyber1024####
print("1024")
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
pk, sk = kyberPy.kyber.Kyber1024.keygen()
#stop
endtime = time.perf_counter()
#record
timeKyber1024KeyGen = endtime-startime
print(timeKyber1024KeyGen)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
c, key = kyberPy.kyber.Kyber1024.enc(pk)
#stop
endtime = time.perf_counter()
#record
timeKyber1024Enc = endtime-startime
print(timeKyber1024Enc)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
_key = kyberPy.kyber.Kyber1024.dec(c, sk)
#stop
endtime = time.perf_counter()
#record
timeKyber1024Dec = endtime-startime
print(timeKyber1024Dec)

###Falcon###
#Creating byte array to test
string = "This is the test string"
byteArray = bytearray()
byteArray.extend(map(ord,string))
print("Falcon")
####1024####
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
sk = falconPy.falcon.SecretKey(1024)
pk = falconPy.falcon.PublicKey(sk)
#stop
endtime = time.perf_counter()
#record
falconKeyGen1024 = endtime-startime
print(falconKeyGen1024)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig = sk.sign(byteArray)
#stop
endtime = time.perf_counter()
#record
falconSigning1024 = endtime - startime
print(falconSigning1024)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
pk.verify(byteArray,sig)
#stop
endtime = time.perf_counter()
falconVerify1024 = endtime-startime
print(falconVerify1024)
#record
####512####
print("512")
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
sk = falconPy.falcon.SecretKey(512)
pk = falconPy.falcon.PublicKey(sk)
#stop
endtime = time.perf_counter()
#record
falconKeyGen512 = endtime-startime
print(falconKeyGen512)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig = sk.sign(byteArray)
#stop
endtime = time.perf_counter()
#record
falconSigning512 = endtime - startime
print(falconSigning512)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
pk.verify(byteArray, sig)
#stop
endtime = time.perf_counter()
#record
falconVerify512 = endtime - startime
print(falconVerify512)
####256####
print("256")
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
sk = falconPy.falcon.SecretKey(256)
pk = falconPy.falcon.PublicKey(sk)
#stop
endtime = time.perf_counter()
#record
falconKeyGen256 = endtime - startime
print(falconKeyGen256)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig = sk.sign(byteArray)
#stop
endtime = time.perf_counter()
#record
falconSigning256 = endtime - startime
print(falconSigning256)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
pk.verify(byteArray, sig)
#stop
endtime = time.perf_counter()
#record
falconVerify256 = endtime - startime
print(falconVerify256)
###Dilithium###
print("Dilithium")
####Dilithium2####
print("Dilithium2")
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
pk,sk = dilithiumPy.dilithium.Dilithium2.keygen()
#stop
endtime = time.perf_counter()
#record
dilithium2 = endtime - startime
print(dilithium2)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig =  dilithiumPy.dilithium.Dilithium2.sign(sk,byteArray)
#stop
endtime = time.perf_counter()
#record
dilithium2Signing = endtime - startime
print(dilithium2Signing)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
dilithiumPy.dilithium.Dilithium2.verify(pk, byteArray, sig)
#stop
endtime = time.perf_counter()
#record
dilithium2Verify = endtime - startime
print(dilithium2Verify)
####Dilithium3####
print("Dilithium3")
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
pk,sk = dilithiumPy.dilithium.Dilithium3.keygen()
#stop
endtime = time.perf_counter()
#record
dilithium3 = endtime - startime
print(dilithium3)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig =  dilithiumPy.dilithium.Dilithium3.sign(sk,byteArray)
#stop
endtime = time.perf_counter()
#record
dilithium3Signing = endtime - startime
print(dilithium3Signing)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
dilithiumPy.dilithium.Dilithium3.verify(pk, byteArray, sig)
#stop
endtime = time.perf_counter()
#record
dilithium3Verify = endtime - startime
print(dilithium3Verify)
####Dilithium5####
print("Dilithium5")
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
pk,sk = dilithiumPy.dilithium.Dilithium5.keygen()
#stop
endtime = time.perf_counter()
#record
dilithium5 = endtime - startime
print(dilithium5)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig =  dilithiumPy.dilithium.Dilithium5.sign(sk,byteArray)
#stop
endtime = time.perf_counter()
#record
dilithium5Signing = endtime - startime
print(dilithium5Signing)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
dilithiumPy.dilithium.Dilithium5.verify(pk, byteArray, sig)
#stop
endtime = time.perf_counter()
#record
dilithium5Verify = endtime - startime
print(dilithium5Verify)
###Sphincs+###
print("Sphincs+")
####Sphincs128s####
print("Sphincs128s")
sphincs128s = Sphincs()
sphincs128s.set_n = 16
sphincs128s.set_h =  63
sphincs128s.set_d = 7
sphincs128s.set_a = 12
sphincs128s.set_k = 14
sphincs128s.set_w = 16
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
sk,pk = sphincs128s.generate_key_pair()
#stop
endtime = time.perf_counter()
#record
sphincs128sKeyGen = endtime - startime
print(sphincs128sKeyGen)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig =  sphincs128s.sign(byteArray,sk)
#stop
endtime = time.perf_counter()
#record
sphincs128sSigning = endtime - startime
print(sphincs128sSigning)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
sphincs128s.verify(sig,byteArray,pk)
#stop
endtime = time.perf_counter()
#record
sphincs128sVerify = endtime - startime
print(sphincs128sVerify)
####Sphincs128f####
print("Sphincs128f")
sphincs128f = Sphincs()
sphincs128f.set_n = 16
sphincs128f.set_h =  66
sphincs128f.set_d = 22
sphincs128f.set_a = 6
sphincs128f.set_k = 33
sphincs128f.set_w = 16
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
sk,pk = sphincs128f.generate_key_pair()
#stop
endtime = time.perf_counter()
#record
sphincs128fKeyGen = endtime - startime
print(sphincs128fKeyGen)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig =  sphincs128f.sign(byteArray,sk)
#stop
endtime = time.perf_counter()
#record
sphincs128fSigning = endtime - startime
print(sphincs128fSigning)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
sphincs128f.verify(sig,byteArray,pk)
#stop
endtime = time.perf_counter()
#record
sphincs128fVerify = endtime - startime
print(sphincs128fVerify)
####Sphincs192s####
print("Sphincs192s")
sphincs192s = Sphincs()
sphincs192s.set_n = 24
sphincs192s.set_h =  63
sphincs192s.set_d = 7
sphincs192s.set_a = 14
sphincs192s.set_k = 17
sphincs192s.set_w = 16
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
sk,pk = sphincs192s.generate_key_pair()
#stop
endtime = time.perf_counter()
#record
sphincs192sKeyGen = endtime - startime
print(sphincs192sKeyGen)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig =  sphincs192s.sign(byteArray,sk)
#stop
endtime = time.perf_counter()
#record
sphincs192sSigning = endtime - startime
print(sphincs192sSigning)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
sphincs192s.verify(sig,byteArray,pk)
#stop
endtime = time.perf_counter()
#record
sphincs192sVerify = endtime - startime
print(sphincs192sVerify)
####Sphincs192f####
print("Sphincs192f")
sphincs192f = Sphincs()
sphincs192f.set_n = 24
sphincs192f.set_h =  66
sphincs192f.set_d = 22
sphincs192f.set_a = 8
sphincs192f.set_k = 33
sphincs192f.set_w = 16
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
sk,pk = sphincs192f.generate_key_pair()
#stop
endtime = time.perf_counter()
#record
sphincs192fKeyGen = endtime - startime
print(sphincs192fKeyGen)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig =  sphincs192f.sign(byteArray,sk)
#stop
endtime = time.perf_counter()
#record
sphincs192fSigning = endtime - startime
print(sphincs192fSigning)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
sphincs192f.verify(sig,byteArray,pk)
#stop
endtime = time.perf_counter()
#record
sphincs192fVerify = endtime - startime
print(sphincs192fVerify)
####Sphincs256s####
print("Sphincs256s")
sphincs256s = Sphincs()
sphincs256s.set_n = 32
sphincs256s.set_h =  64
sphincs256s.set_d = 8
sphincs256s.set_a = 14
sphincs256s.set_k = 22
sphincs256s.set_w = 16
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
sk,pk = sphincs256s.generate_key_pair()
#stop
endtime = time.perf_counter()
#record
sphincs256sKeyGen = endtime - startime
print(sphincs256sKeyGen)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig =  sphincs256s.sign(byteArray,sk)
#stop
endtime = time.perf_counter()
#record
sphincs256sSigning = endtime - startime
print(sphincs256sSigning)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
sphincs256s.verify(sig,byteArray,pk)
#stop
endtime = time.perf_counter()
#record
sphincs256sVerify = endtime - startime
print(sphincs256sVerify)
####Sphincs256f####
print("Sphincs256f")
sphincs256f = Sphincs()
sphincs256f.set_n = 32
sphincs256f.set_h =  68
sphincs256f.set_d = 17
sphincs256f.set_a = 9
sphincs256f.set_k = 35
sphincs256f.set_w = 16
#####Keygen#####
print("KeyGen")
#start timer
startime = time.perf_counter()
#excute
sk,pk = sphincs256f.generate_key_pair()
#stop
endtime = time.perf_counter()
#record
sphincs256fKeyGen = endtime - startime
print(sphincs256fKeyGen)
#####Encap#####
print("Encap")
#start timer
startime = time.perf_counter()
#excute
sig =  sphincs256f.sign(byteArray,sk)
#stop
endtime = time.perf_counter()
#record
sphincs256fSigning = endtime - startime
print(sphincs256fSigning)
#####Decap#####
print("Decap")
#start timer
startime = time.perf_counter()
#excute
sphincs256f.verify(sig,byteArray,pk)
#stop
endtime = time.perf_counter()
#record
sphincs256fVerify = endtime - startime
print(sphincs256fVerify)

