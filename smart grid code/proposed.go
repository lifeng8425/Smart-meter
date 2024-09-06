package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"time"
)

var (
	Byt = int(16)
)

func main() {

	echo := int(1e5)
	SMrun(echo)
	SPrun(echo)

	SMrun19(echo)
	SPrun19(echo)

	SMrun24(echo)
	SPrun24(echo)
}

// r-2,h-16,and-22,De-2,En-2,oxr20
func SMrun19(echo int) { //r-1,h-6,De-1,and-7,Oxr-6
	fmt.Print("SMrun19 echo:", echo, "; time:")
	IDi := RS(Byt)
	r1 := RS(Byt)
	key := RS(Byt)
	Auji := AesEncryptCBC(RS(3*Byt), key)
	// hash := md5.New()
	ACK := Hmd5(RS(2 * Byt))
	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		//round1
		r2 := RS(Byt)
		getOxr(r2, Hmd5(getAnd(IDi, r1)))
		//round3
		Hmd5(getOxr3(IDi, r1, r2)) //k
		AesDecryptCBC(Auji, key)
		r3 := getOxr(r1, Hmd5(getAnd(getOxr(IDi, r2), r1)))
		SK := Hmd5(getAnd4(IDi, r1, r2, r3))
		Hmd5(getAnd(SK, r3)) //AUij
		Ack := Hmd5(getAnd(getOxr(r3, r2), r1))
		ifequi(ACK, Ack)
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, Ot-ot)
}
func SPrun19(echo int) { //r-1,h-10,De-1,En-2,and-15,Oxr-14
	fmt.Print("SPrun19 echo:", echo, "; time:")
	origdata := RS(Byt * 2)
	IDj := RS(Byt)
	s := RS(Byt)
	b1 := RS(Byt)
	// hash := md5.New()
	M := AesEncryptCBC(origdata, s)
	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		AesDecryptCBC(M, s)
		IDi := getOxr(Hmd5(getAnd(IDj, s)), b1)
		// fmt.Println(len(Hmd5(getAnd(IDj, s))))
		r1 := getOxr(b1, IDi)
		Q := Hmd5(getOxr3(getAnd(IDi, IDj), s, r1))
		ifequi(Q, b1)
		ifequi(Q, b1)
		r2 := getOxr(b1, Hmd5(getAnd(IDi, r1)))
		M = AesEncryptCBC(getAnd(getOxr(b1, IDi), getOxr(r2, IDi)), s)
		r3 := RS(Byt)
		k := Hmd5(getOxr3(IDi, r1, r2))
		A1 := getOxr(Hmd5(getAnd(getOxr(IDi, r2), r1)), r3)
		A2 := Hmd5(getAnd3(IDi, r1, r2))
		Auji := AesEncryptCBC(getAnd3(A1, A2, M), k) //Auji
		SK := Hmd5(getAnd4(IDi, r1, r2, r3))         //SK
		ifequi(Auji, Hmd5(getAnd(SK, r3)))
		Q = Hmd5(getOxr3(getAnd(IDi, IDj), s, r2))
		Hmd5(getAnd(getOxr(r2, r3), r1)) //ACK
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, Ot-ot)
}

// r-1,h-14
func SMrun(echo int) { //h-6,1-random
	fmt.Print("SMrun echo:", echo, "; time:")
	V1 := RS(Byt)
	V2 := RS(Byt)
	r1 := RS(Byt)
	IDi := RS(Byt)
	// hash := md5.New()
	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		r3 := RS(Byt)
		X := getOxr(r3, getAnd(r1, IDi))
		Hmd5(getAnd(IDi, X)) //Auij
		//sent(r1,M,X,Auij)
		//get(Auji,V1,V2)
		r2 := getOxr(V1, Hmd5(getAnd(IDi, r1)))
		M := getOxr(V2, Hmd5(getAnd3(IDi, r1, r2)))
		sk := Hmd5(getAnd3(IDi, r2, r3))
		Hmd5(getAnd(sk, M)) //Auji
		//if Auji = Auji^*
		//update
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, Ot-ot)
}
func SPrun(echo int) { //h-8
	fmt.Print("SPrun echo:", echo, "; time:")
	r1 := RS(Byt)
	r2 := RS(Byt)
	M := RS(Byt)
	s := RS(Byt)
	IDj := RS(Byt)
	X := RS(Byt)
	//if r1
	// hash := md5.New()
	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		//check if exist r1
		IDi := getOxr(M, Hmd5(getAnd3(r2, s, IDj)))
		Hmd5(getAnd(IDi, X)) //Auij
		//if Auij = Auij*
		r3 := getOxr(X, Hmd5(getAnd(r1, IDi)))
		M := getOxr(M, Hmd5(getAnd3(r3, s, IDj)))
		getOxr(r2, Hmd5(getAnd(IDi, r1)))     //V1
		getOxr(M, Hmd5(getAnd3(IDi, r1, r2))) //V2
		SK := Hmd5(getAnd3(IDi, r2, r3))
		Hmd5(getAnd(SK, M)) //Auji
		//sent
		//update
	}

	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, Ot-ot)
}

// 4-random 15-h 1-de
func SMrun24(echo int) { //2-random 1-de 8-h
	fmt.Print("SMrun24 echo:", echo, "; time:")
	IDi := RS(Byt)
	PW := RS(Byt)
	V3 := RS(Byt * 4)
	c1 := RS(Byt)
	c2 := RS(Byt)
	k := RS(Byt)
	MID := RS(Byt)
	EM := AesEncryptCBC(getAnd(c1, c2), k)
	IDs := RS(Byt)
	Ns := RS(Byt)
	B := RS(Byt)
	t := RS(Byt)
	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		r := getOxr(B, t) //simulating rep operation.the real rep operation is more complex than Oxr
		Ki := Hmd5(getAnd3(IDi, r, PW))
		EID := getOxr4(MID, Ki, PW, r)
		AesDecryptCBC(EM, k) //Decrypt to get c1,c2.
		HPW := Hmd5(getAnd(PW, r))
		I := getOxr3(c1, HPW, IDi)
		ifequi(c2, Hmd5(getAnd4(IDi, PW, r, I))) //c2*
		Ni := RS(Byt)
		Nt := RS(Byt)
		getOxr(getAnd4(IDi, Ni, EID, Nt), Hmd5(getAnd(I, Nt))) //V1
		Hmd5(getAnd5(IDi, Ni, I, EID, Nt))                     //V2
		//round2
		getOxr(V3, Hmd5(getAnd3(IDi, Ni, I))) //IDs,Ns,EID,Ni
		ifequi(Ni, Ni)
		SK := Hmd5(getAnd5(I, IDi, IDs, Ni, Ns))
		V4 := Hmd5(getAnd5(Ns, IDs, I, EID, SK))
		ifequi(V4, V4)
		MID = getOxr3(EID, EID, MID) //update MID
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, Ot-ot)
}
func SPrun24(echo int) { //2-random 7-h
	fmt.Print("SPrun24 echo:", echo, "; time:")
	EID := RS(Byt)
	ES := RS(Byt)
	Ks := RS(Byt)
	IDs := RS(Byt)
	V1 := RS(4 * Byt)
	Nt := RS(Byt)
	Ni := RS(Byt)
	IDi := RS(Byt)
	ot := time.Now().UnixNano()
	for i := 0; i < echo; i++ {
		ifequi(EID, EID) //check EID
		I := getOxr(Hmd5((getAnd3(Ks, EID, IDs))), ES)
		getOxr(V1, Hmd5(getAnd(I, Nt))) //IDi,Ni,EID,Nt
		ifequi(EID, EID)
		ifequi(Nt, Nt)
		V2 := Hmd5(getAnd5(IDi, Ni, I, EID, Nt)) //V2
		ifequi(V2, V2)
		EID = RS(Byt) //select EID
		Ns := RS(Byt)
		SK := Hmd5(getAnd5(I, IDi, IDs, Ni, Ns))
		getOxr(getAnd4(IDs, Ns, EID, Nt), Hmd5(getAnd3(IDi, Ni, I))) //V3
		Hmd5(getAnd5(Ns, IDs, I, EID, SK))                           //V4
		//update
		getOxr(I, Hmd5(getAnd3(Ks, EID, IDs))) //update ES
	}
	Ot := time.Now().UnixNano()
	oot := float64(Ot - ot)
	fmt.Println(oot/1e6, Ot-ot)
}

func RS(Byt int) []byte {
	r := make([]byte, Byt)
	rand.Read(r)
	return r
}
func ifequi(a []byte, b []byte) bool {
	la := len(a)
	lb := len(b)
	if la != lb {
		return false
	}
	for i := 0; i < la; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func get16(a []byte) []byte {
	c := make([]byte, 16)
	for i := 0; i < 16; i++ {
		c[i] = a[i]
	}
	return c
}
func getAnd(a []byte, b []byte) []byte {
	la := len(a)
	lb := len(b)
	c := make([]byte, la+lb)
	for i := 0; i < la; i++ {
		c[i] = a[i]
	}
	for i := la; i < la+lb; i++ {
		c[i] = b[i-la]
	}
	return c
}
func getAnd3(a []byte, b []byte, c []byte) []byte {
	la := len(a)
	lb := len(b)
	lc := len(c)
	cc := make([]byte, la+lb+lc)
	i := 0
	for ; i < la; i++ {
		cc[i] = a[i]
	}
	for ; i < la+lb; i++ {
		cc[i] = b[i-la]
	}
	for ; i < la+lb+lc; i++ {
		cc[i] = c[i-la-lb]
	}
	return cc
}
func getAnd4(a []byte, b []byte, c []byte, d []byte) []byte {
	la := len(a)
	lb := len(b)
	lc := len(c)
	ld := len(d)
	cc := make([]byte, la+lb+lc+ld)
	i := 0
	for ; i < la; i++ {
		cc[i] = a[i]
	}
	for ; i < la+lb; i++ {
		cc[i] = b[i-la]
	}
	for ; i < la+lb+lc; i++ {
		cc[i] = c[i-la-lb]
	}
	for ; i < la+lb+lc+ld; i++ {
		cc[i] = c[i-la-lb-lc]
	}
	return cc
}
func getAnd5(a []byte, b []byte, c []byte, d []byte, e []byte) []byte {
	la := len(a)
	lb := len(b)
	lc := len(c)
	ld := len(d)
	le := len(e)
	cc := make([]byte, la+lb+lc+ld+le)
	i := 0
	for ; i < la; i++ {
		cc[i] = a[i]
	}
	for ; i < la+lb; i++ {
		cc[i] = b[i-la]
	}
	for ; i < la+lb+lc; i++ {
		cc[i] = c[i-la-lb]
	}
	for ; i < la+lb+lc+ld; i++ {
		cc[i] = c[i-la-lb-lc]
	}
	for ; i < la+lb+lc+ld+le; i++ {
		cc[i] = c[i-la-lb-lc-ld]
	}
	return cc
}
func getOxr(a []byte, b []byte) []byte {
	la := len(a)
	lb := len(b)
	if la > lb {
		c := make([]byte, la)
		i := 0
		t := 0
		for ; i < la; i++ {
			if i%lb == 0 {
				t = 0
			}
			c[i] = a[i] ^ b[t]
			t++
		}
		return c
	}
	c := make([]byte, lb)
	i := 0
	t := 0
	for ; i < lb; i++ {
		if i%la == 0 {
			t = 0
		}
		c[i] = b[i] ^ a[t]
		t++
	}
	return c
}
func getOxr3(a []byte, b []byte, c []byte) []byte {
	la := len(a)
	lb := len(b)
	lc := len(c)
	if la >= lb && la >= lc {
		cc := make([]byte, la)
		i := 0
		t := 0
		tt := 0
		for ; i < la; i++ {
			if i%lb == 0 {
				t = 0
			}
			if i%lc == 0 {
				tt = 0
			}
			cc[i] = a[i] ^ b[t] ^ c[tt]
			t++
			tt++
		}
		return cc
	}
	if lb >= la && lb >= lc {
		cc := make([]byte, lb)
		i := 0
		t := 0
		tt := 0
		for ; i < lb; i++ {
			if i%la == 0 {
				t = 0
			}
			if i%lc == 0 {
				tt = 0
			}
			cc[i] = b[i] ^ a[t] ^ c[tt]
			t++
			tt++
		}
		return cc
	}
	cc := make([]byte, lc)
	i := 0
	t := 0
	tt := 0
	for ; i < lc; i++ {
		if i%la == 0 {
			t = 0
		}
		if i%lb == 0 {
			tt = 0
		}
		cc[i] = c[i] ^ a[t] ^ b[tt]
		t++
		tt++
	}
	return cc
}
func getOxr4(a []byte, b []byte, c []byte, d []byte) []byte {
	la := len(a)
	lb := len(b)
	lc := len(c)
	ld := len(d)
	if la >= lb && la >= lc && la >= ld {
		cc := make([]byte, la)
		i := 0
		t := 0
		tt := 0
		ttt := 0
		for ; i < la; i++ {
			if i%lb == 0 {
				t = 0
			}
			if i%lc == 0 {
				tt = 0
			}
			if i%ld == 0 {
				ttt = 0
			}
			cc[i] = a[i] ^ b[t] ^ c[tt] ^ d[ttt]
			t++
			tt++
			ttt++
		}
		return cc
	}
	if lb >= la && lb >= lc && lb >= ld {
		cc := make([]byte, lb)
		i := 0
		t := 0
		tt := 0
		ttt := 0
		for ; i < lb; i++ {
			if i%la == 0 {
				t = 0
			}
			if i%lc == 0 {
				tt = 0
			}
			if i%ld == 0 {
				ttt = 0
			}
			cc[i] = b[i] ^ a[t] ^ c[tt] ^ d[ttt]
			t++
			tt++
			ttt++
		}
		return cc
	}
	if ld >= la && ld >= lc && ld >= lb {
		cc := make([]byte, ld)
		i := 0
		t := 0
		tt := 0
		ttt := 0
		for ; i < ld; i++ {
			if i%la == 0 {
				t = 0
			}
			if i%lc == 0 {
				tt = 0
			}
			if i%lb == 0 {
				ttt = 0
			}
			cc[i] = d[i] ^ a[t] ^ c[tt] ^ b[ttt]
			t++
			tt++
			ttt++
		}
		return cc
	}
	cc := make([]byte, lc)
	i := 0
	t := 0
	tt := 0
	ttt := 0
	for ; i < lc; i++ {
		if i%la == 0 {
			t = 0
		}
		if i%lb == 0 {
			tt = 0
		}
		if i%ld == 0 {
			ttt = 0
		}
		cc[i] = c[i] ^ a[t] ^ b[tt] ^ d[ttt]
		t++
		tt++
		ttt++
	}
	return cc
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}
func Hmd5(s []byte) []byte {
	h := md5.New()
	h.Write(s)
	return h.Sum(nil)
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
