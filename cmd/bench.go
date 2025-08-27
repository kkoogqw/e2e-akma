package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/crypt0/paillier"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
	"math/big"
	"ppakma/osign"
	"sync"
	"time"
)

func generateChallenge() string {
	r1 := bigint.GetRandom().String()
	r2 := bigint.GetRandom().String()
	r := fmt.Sprintf("%s%s", r1, r2)
	hash := sha256.New()
	hash.Write([]byte(r))
	return hex.EncodeToString(hash.Sum(nil))
}

func throughputTestChallengeGen(size int) {
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < size; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = generateChallenge()

		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("Executed per server gen-challenge in %v\n", elapsed)
}

func throughputTest2POSServerKeyGen(size int) {
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < size; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = osign.GenerateServerKeys()

		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("Executed per server key-gen in %v\n", elapsed)
}

func throughputTest2POSServerCommit(size int) {
	serverKey := osign.GenerateServerKeys()
	clientKey, _ := osign.GenerateClientKeys(serverKey.PubKey)
	_ = serverKey.PubKey.Q.ScalarMul(clientKey.X)
	_, comm := osign.ClientSign1()

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < size; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = osign.ServerSign1(*comm)
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("Executed per server key-commit in %v\n", elapsed)

}

func throughputTest2POSServerFinal(size int) {
	m := "hello"
	serverKey := osign.GenerateServerKeys()
	clientKey, _ := osign.GenerateClientKeys(serverKey.PubKey)
	_ = serverKey.PubKey.Q.ScalarMul(clientKey.X)
	clientState, comm := osign.ClientSign1()
	serverState, serverOsPk := osign.ServerSign1(*comm)
	clientState, clientPreSign, _ := osign.ClientSign2([]byte(m), clientKey, clientState, serverOsPk)

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < size; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = osign.ServerSign2(serverKey.PrivKey, serverState, clientPreSign)
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("Executed per server final in %v\n", elapsed)

}

func throughputTestAmortized2POSServerCommit(size int, infoList []*osign.ServerPrecomputedInfo) {
	serverKey := osign.GenerateServerKeys()
	clientKey, _ := osign.GenerateClientKeys(serverKey.PubKey)
	_ = serverKey.PubKey.Q.ScalarMul(clientKey.X)
	_, comm := osign.ClientSign1()

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < size; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = osign.AmortizedServerSign1(*comm, infoList[i])
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("Executed per amortized server key-commit in %v\n", elapsed)

}

func throughputTestAmortized22POSServerFinal(size int, infoList []*osign.ServerPrecomputedInfo) {
	m := "hello"
	serverKey := osign.GenerateServerKeys()
	clientKey, _ := osign.GenerateClientKeys(serverKey.PubKey)
	_ = serverKey.PubKey.Q.ScalarMul(clientKey.X)
	clientState, comm := osign.ClientSign1()
	serverState, serverOsPk := osign.ServerSign1(*comm)
	clientState, clientPreSign, _ := osign.ClientSign2([]byte(m), clientKey, clientState, serverOsPk)

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < size; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = osign.AmortizedServerSign2(serverKey.PrivKey, serverState, clientPreSign, infoList[i])
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("Executed per amortized server final in %v\n", elapsed)

}

func throughputTest2POSServerVerify(size int) {
	m := "hello"
	serverKey := osign.GenerateServerKeys()
	clientKey, _ := osign.GenerateClientKeys(serverKey.PubKey)
	vk := serverKey.PubKey.Q.ScalarMul(clientKey.X)
	clientState, comm := osign.ClientSign1()
	serverState, serverOsPk := osign.ServerSign1(*comm)
	clientState, clientPreSign, _ := osign.ClientSign2([]byte(m), clientKey, clientState, serverOsPk)
	serverPreSign, _ := osign.ServerSign2(serverKey.PrivKey, serverState, clientPreSign)
	outSig, _ := osign.ClientFinal(clientState, serverPreSign)
	mhash := bigint.HashBytesToBigInt([]byte(m))
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < size; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			verfied_ := ecdsa.Verify(vk, mhash, outSig, secp256k1.GetSecp256k1())
			if !verfied_ {
				fmt.Println("Verification failed")
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("Executed per server verify in %v\n", elapsed)
}

func main() {
	//batchSize := 500
	//pre := make([]*osign.ServerPrecomputedInfo, batchSize)
	//for i := 0; i < batchSize; i++ {
	//	pre[i] = osign.PrecomputeServerSign(osign.GenerateServerKeys().PrivKey)
	//}
	//throughputTestChallengeGen(batchSize)
	//throughputTest2POSServerKeyGen(batchSize)
	//throughputTest2POSServerCommit(batchSize)
	//throughputTestAmortized2POSServerCommit(batchSize, pre)
	//throughputTest2POSServerFinal(batchSize)
	//throughputTestAmortized22POSServerFinal(batchSize, pre)
	//throughputTest2POSServerVerify(batchSize)
	//fmt.Println("=====================================")

	singleInst()
}

func singleInst() {
	throughputTest2POSServerFinal(1)

	// test pailliar
	paillierKeyPair, _ := paillier.GenerateKey(rand.Reader)
	message := "hello"
	m := bigint.HashBytesToBigInt([]byte(message))
	// timer
	start := time.Now()
	c, _ := paillier.Encrypt(&paillierKeyPair.PublicKey, m.Bytes())
	elapsed := time.Since(start)
	fmt.Printf("Executed per paillier encrypt in %v\n", elapsed)

	start = time.Now()
	t := new(big.Int).Mul(new(big.Int).SetBytes(c), new(big.Int).SetBytes(c))
	r := t.Mod(t, paillierKeyPair.PublicKey.NN)
	end := time.Now()
	fmt.Printf("Executed per paillier decrypt in %v\n", end.Sub(start))

	start = time.Now()
	r = new(big.Int).Exp(r, paillierKeyPair.PublicKey.N, paillierKeyPair.PublicKey.NN)
	end = time.Now()
	fmt.Printf("Executed per paillier decrypt in %v\n", end.Sub(start))

	fmt.Println(r)
}
