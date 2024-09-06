package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"log"
	"time"
)
//Test the running time of each component
var (
	Byt = int(16)
	//there data are measured in the experiment
	SMTh = float64(1803.976)
	SMTd = float64(17832.978)
	SMTe = float64(19352.545)
	SMTm = float64(10468943.382)
	SPTh = float64(146.467)
	SPTd = float64(707.139)
	SPTe = float64(853.718)
	SPTm = float64(67042.053)
)

func main() {

	echo := int(1e3)
	Xortime(echo)
	hashtime(echo)
	randomtime(echo)
	encryCBCtime(echo, int(60))
	encryCBCtime(echo, int(80))
	decryCBCtime(echo, int(60))
	decryCBCtime(echo, int(80))
	CurveAddTime(echo)
	CurveMulTime(echo)
	Runtime()
}
func Runtime() {//compute the runtime
	P17SM := 7*SMTh + 1*SMTd
	P17SP := 9*SPTh + 1*SPTd + 2*SPTe
	P18SM := 8*SMTh + 1*SMTd
	P18SP := 7 * SPTh
	P19SM := 5*SMTh + 2*SMTm
	P19SP := 11*SPTh + 2*SPTm
	P20SM := 4*SMTh + 1*SMTd + 1*SMTe + 3*SMTm
	P20SP := 6*SPTh + 1*SPTd + 1*SPTe + 4*SPTm
	P21SM := 4*SMTh + 2*SMTm
	P21SP := 3*SPTh + 2*SPTm
	OurSM := 6 * SMTh
	OurSP := 8 * SPTh
	fmt.Println("Protocol17 SM:", P17SM, "ns  SP:", P17SP, "ns", "Total", P17SM+P17SP, "ns")
	fmt.Println("Protocol18 SM:", P18SM, "ns  SP:", P18SP, "ns", "Total", P18SM+P18SP, "ns")
	fmt.Println("Protocol19 SM:", P19SM, "ns  SP:", P19SP, "ns", "Total", P19SM+P19SP, "ns")
	fmt.Println("Protocol20 SM:", P20SM, "ns  SP:", P20SP, "ns", "Total", P20SM+P20SP, "ns")
	fmt.Println("Protocol21 SM:", P21SM, "ns  SP:", P21SP, "ns", "Total", P21SM+P21SP, "ns")
	fmt.Println("Our Protocol SM:", OurSM, "ns  SP:", OurSP, "ns", "Total", OurSM+OurSP, "ns")
}
func RS(Byt int) []byte {
	r := make([]byte, Byt)
	rand.Read(r)
	return r
}
func CurveMulTime(echo int) {
	curve := elliptic.P256()

	// 生成两个密钥对
	privateKey1, _ := ecdsa.GenerateKey(curve, rand.Reader)
	privateKey2, _ := ecdsa.GenerateKey(curve, rand.Reader)
	ot := time.Now()
	// 使用对方的公钥和自己的私钥生成共享密钥
	for i := 0; i < echo; i++ {
		x1, _ := curve.ScalarMult(privateKey2.PublicKey.X, privateKey2.PublicKey.Y, privateKey1.D.Bytes())
		x1.Bytes()
	}

	Ot := time.Since(ot)
	fmt.Println("eccMul", Ot)
}

func CurveAddTime(echo int) {
	curve := elliptic.P256()
	a, _ := rand.Int(rand.Reader, curve.Params().P)
	b, _ := rand.Int(rand.Reader, curve.Params().P)
	x1, y1 := curve.ScalarBaseMult(a.Bytes())
	x2, y2 := curve.ScalarBaseMult(b.Bytes())
	if !curve.IsOnCurve(x1, y1) {
		log.Fatalf("x1: %#v, y1: %#v not on curve", x1, y1)
	}
	if !curve.IsOnCurve(x2, y2) {
		log.Fatalf("x2: %#v, y2: %#v not on curve", x2, y2)
	}
	// invert one point
	y2 = y2.Neg(y2)
	y2 = y2.Mod(y2, curve.Params().P)
	// do addition on the curve
	x3, y3 := curve.Add(x1, y1, x2, y2)
	ot := time.Now()
	for i := 0; i < echo; i++ {
		x3, y3 = curve.Add(x1, y1, x2, y2)
	}
	Ot := time.Since(ot)
	fmt.Println("CEEADD:", Ot)
	if !curve.IsOnCurve(x3, y3) {
		log.Fatalf("x3: %#v, y3: %#v not on curve", x3, y3)
	}

}
func hashtime(echo int) {
	b := make([]byte, Byt)
	rand.Read(b)
	ot := time.Now()
	// h := md5.New()
	for i := 0; i < echo; i++ {
		// md5.Sum(b)
		h := md5.New()
		h.Write(b)
		h.Sum(nil)
	}
	Ot := time.Since(ot)
	fmt.Println("hash:", Ot)
}
func randomtime(echo int) {
	ot := time.Now()
	b := make([]byte, Byt)
	for i := 0; i < echo; i++ {
		rand.Read(b)
	}
	Ot := time.Since(ot)
	fmt.Println("rand:", Ot)
}
func encryCBCtime(echo, length int) {
	key := make([]byte, 16)
	origData := make([]byte, length)
	encryCBC := make([]byte, length)
	rand.Read(origData)
	rand.Read(key)
	ot := time.Now()
	for i := 0; i < echo; i++ {
		encryCBC = AesEncryptCBC(origData, key)
	}
	Ot := time.Since(ot)
	fmt.Println("aesEn:", Ot)
	origData = encryCBC
}
func decryCBCtime(echo, length int) {
	key := make([]byte, 16)
	origData := make([]byte, length)
	// encryCBC := make([]byte, length)
	rand.Read(origData)
	rand.Read(key)
	encryCBC := AesEncryptCBC(origData, key)
	ot := time.Now()
	for i := 0; i < echo; i++ {
		AesDecryptCBC(encryCBC, key)
	}
	Ot := time.Since(ot)
	fmt.Println("aesDe", Ot)
	origData = encryCBC
}
func Xortime(echo int) {
	a := make([]byte, Byt)
	b := make([]byte, Byt)
	c := make([]byte, Byt)
	rand.Read(a)
	rand.Read(b)
	ot := time.Now()
	for i := 0; i < echo; i++ {
		for j := 0; j < Byt; j++ {
			c[j] = a[j] ^ b[j]
		}
	}
	Ot := time.Since(ot)
	fmt.Println("Xor:", Ot)
}

// CBC
func AesEncryptCBC(origData []byte, key []byte) (encrypted []byte) {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	origData = pkcs5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	encrypted = make([]byte, len(origData))
	blockMode.CryptBlocks(encrypted, origData)
	return encrypted
}
func AesDecryptCBC(encrypted []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	decrypted = make([]byte, len(encrypted))
	blockMode.CryptBlocks(decrypted, encrypted)
	decrypted = pkcs5UnPadding(decrypted)
	return decrypted
}
func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
