package ue

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
	"log"
	"net/http"
	"ppakma/af"
	"ppakma/hn"
	"ppakma/osign"
	"time"
)

type hnRegRequestResponse struct {
	Message   string                   `json:"message"`
	PublicKey osign.ApiServerPublicKey `json:"public_key"`
}

type hnRegCommitResponse struct {
	Message      string             `json:"message"`
	UidSignature ecdsa.Signature    `json:"uid_signature"`
	OsignPk      osign.ApiEcPoint   `json:"osign_pk"`
	OsignPf      osign.ApiDLogProof `json:"osign_pf"`
}

type hnRegFinishResponse struct {
	Message string `json:"message"`
	Cipher  string `json:"cipher"`
}

type hnLoginRequestResponse struct {
	Message  string             `json:"message"`
	OsignTpk osign.ApiEcPoint   `json:"osign_tpk"`
	OsignTpf osign.ApiDLogProof `json:"osign_tpf"`
}

type hnLoginFinishResponse struct {
	Message string `json:"message"`
	Cipher  string `json:"cipher"`
}

type afRegRequestResponse struct {
	Message   string `json:"message"`
	Challenge string `json:"challenge"`
}

type afRegFinishResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type afLoginRequestResponse struct {
	Message   string `json:"message"`
	Challenge string `json:"challenge"`
}

type afLoginFinishResponse struct {
	Message string `json:"message"`
}

func GenerateUID() string {
	r1 := bigint.GetRandom().String()
	r2 := bigint.GetRandom().String()
	r := fmt.Sprintf("%s%s", r1, r2)
	hash := sha256.New()
	hash.Write([]byte(r))
	return hex.EncodeToString(hash.Sum(nil))
}

func GenerateSUPI() string {
	// produce a random 15 digits as the SUPI
	return fmt.Sprintf("%015d", bigint.GetRandom().Int64())
}

func GenerateRandomness() []byte {
	r1 := bigint.GetRandom().String()
	r2 := bigint.GetRandom().String()
	r := fmt.Sprintf("%s%s", r1, r2)
	hash := sha256.New()
	hash.Write([]byte(r))
	return hash.Sum(nil)
}

type ObliviousSignClientBenchmarkStat struct {
	KeyGenTime      time.Duration `json:"key_gen_time"`
	Sign1Time       time.Duration `json:"sign1_time"`
	Sign2Time       time.Duration `json:"sign2_time"`
	Sign3Time       time.Duration `json:"sign3_time"`
	TotalClientTime time.Duration `json:"total_client_time"`
}

func benchmark2POSignature() *ObliviousSignClientBenchmarkStat {
	/// 1. Benchmark the Oblivious Sign
	var obsignStat ObliviousSignClientBenchmarkStat
	//server gen:
	// set timer:
	skeygen_start := time.Now()
	serverKey := osign.GenerateServerKeys()
	skeygen_end := time.Now()
	fmt.Printf(">>> server key gen time: %v\n", skeygen_end.Sub(skeygen_start))

	// client gen:
	// set timer
	ckeygen_start := time.Now()
	clientKey, _ := osign.GenerateClientKeys(serverKey.PubKey)
	ckeygen_end := time.Now()

	fmt.Printf(">>> client key gen time: %v\n", ckeygen_end.Sub(ckeygen_start))
	obsignStat.KeyGenTime = ckeygen_end.Sub(ckeygen_start)

	// compute the vk in server side:
	vk := serverKey.PubKey.Q.ScalarMul(clientKey.X)

	// round 1
	// set timer
	csign1_start := time.Now()
	clientState, comm := osign.ClientSign1()
	csign1_end := time.Now()
	fmt.Printf(">>> client sign1 time: %v\n", csign1_end.Sub(csign1_start))
	obsignStat.Sign1Time = csign1_end.Sub(csign1_start)

	//
	// set timer
	ssign1_start := time.Now()
	serverState, serverOsPk := osign.ServerSign1(*comm)
	ssign1_end := time.Now()
	fmt.Printf(">>> server sign1 time: %v\n", ssign1_end.Sub(ssign1_start))

	// round 2
	message := []byte("test message")
	mhash := bigint.HashBytesToBigInt(message)

	// set timer
	csign2_start := time.Now()
	clientState, clientPreSign, _ := osign.ClientSign2(message, clientKey, clientState, serverOsPk)
	csign2_end := time.Now()
	fmt.Printf(">>> client sign2 time: %v\n", csign2_end.Sub(csign2_start))
	obsignStat.Sign2Time = csign2_end.Sub(csign2_start)

	//
	// set timer
	ssign2_start := time.Now()
	serverPreSign, _ := osign.ServerSign2(serverKey.PrivKey, serverState, clientPreSign)
	ssign2_end := time.Now()
	fmt.Printf(">>> server sign2 time: %v\n", ssign2_end.Sub(ssign2_start))

	// final
	// set timer
	cfinal_start := time.Now()
	outSig, _ := osign.ClientFinal(clientState, serverPreSign)
	cfinal_end := time.Now()
	fmt.Printf(">>> client final time: %v\n", cfinal_end.Sub(cfinal_start))
	obsignStat.Sign3Time = cfinal_end.Sub(cfinal_start)

	// verify the signature
	// set timer
	verf_start := time.Now()
	verfied_ := ecdsa.Verify(vk, mhash, outSig, secp256k1.GetSecp256k1())
	verf_end := time.Now()
	fmt.Printf(">>> verifying (ecdsa) time: %v\n", verf_end.Sub(verf_start))
	fmt.Printf("verifing signature result - verified: %t\n", verfied_)

	obsignStat.TotalClientTime = obsignStat.KeyGenTime + obsignStat.Sign1Time + obsignStat.Sign2Time + obsignStat.Sign3Time
	return &obsignStat
}

type AkmaProtocolBenchmarkStat struct {
	// register:
	NwRegAFReqTime time.Duration `json:"nw_reg_af_req_time"`
	NwRegHNReqTime time.Duration `json:"nw_reg_hn_req_time"`
	NwRegHNComTime time.Duration `json:"nw_reg_hn_com_time"`
	NwRegHNFinTime time.Duration `json:"nw_reg_hn_fin_time"`
	NwRegAFFinTime time.Duration `json:"nw_reg_af_fin_time"`
	CpRegComTime   time.Duration `json:"cp_reg_hn_com_time"`
	CpRegSignTime  time.Duration `json:"cp_reg_sign_time"`
	CpRegFinTime   time.Duration `json:"cp_reg_hn_fin_time"`
	// login:
	NwLoginAfReqTime time.Duration `json:"nw_login_af_req_time"`
	NwLoginHNReqTime time.Duration `json:"nw_login_hn_req_time"`
	NwLoginHNFinTime time.Duration `json:"nw_login_hn_fin_time"`
	NwLoginAFFinTime time.Duration `json:"nw_login_af_fin_time"`
	CpLoginComTime   time.Duration `json:"cp_login_hn_com_time"`
	CpLoginSignTime  time.Duration `json:"cp_login_sign_time"`
	CpLoginFinTime   time.Duration `json:"cp_login_hn_fin_time"`
	// total:
	RegComputationTime   time.Duration `json:"reg_computation_time"`
	RegNetworkTime       time.Duration `json:"reg_network_time"`
	RegTotalTime         time.Duration `json:"reg_total_time"`
	LoginComputationTime time.Duration `json:"login_computation_time"`
	LoginNetworkTime     time.Duration `json:"login_network_time"`
	LoginTotalTime       time.Duration `json:"login_total_time"`
}

func benchmarkAKMA(hnUrl, afUrl string) *AkmaProtocolBenchmarkStat {
	// generate a random user
	afId := "AppFunction@b53ca8af879f65"
	uid := GenerateUID()
	username := "U-" + uid
	supi := "imsi-" + GenerateSUPI()

	// stage 1: register
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := &http.Client{
		Timeout:   time.Minute,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	/// 1. send register request to AF
	regAfReqStart := time.Now()
	param1 := make(map[string]string)
	param1["uid"] = uid
	param1["username"] = username
	regResp, err := sendGetRequest(
		afUrl,
		"/api/af/reg/request",
		param1,
		client)
	if err != nil {
		log.Fatal("Failed to send register request to AF:", err)
		return nil
	}
	//parse the challenge from AF's response
	var chResp afRegRequestResponse
	err = json.Unmarshal(regResp, &chResp)
	if err != nil {
		log.Fatal("Failed to parse register response from AF:", err)
		return nil
	}
	regAfReqTime := time.Now().Sub(regAfReqStart)
	/// 2. send register request to HN
	regHnReqStart := time.Now()
	param2 := make(map[string]string)
	param2["supi"] = supi
	regResp, err = sendGetRequest(
		hnUrl,
		"/api/hn/reg/request",
		param2,
		client)
	if err != nil {
		log.Fatal("Failed to send register request to HN:", err)
		return nil
	}
	var serverOsKeyResp hnRegRequestResponse
	err = json.Unmarshal(regResp, &serverOsKeyResp)
	if err != nil {
		log.Fatal("Failed to parse register response from HN:", err)
		return nil
	}
	serverOsPubKey := &osign.ServerPublicKey{
		Q: osign.ParseEcPoint(&serverOsKeyResp.PublicKey.Q),
		Pi: &osign.DlogProof{
			R: osign.ParseEcPoint(&serverOsKeyResp.PublicKey.Pi.R),
			C: &serverOsKeyResp.PublicKey.Pi.C,
			S: &serverOsKeyResp.PublicKey.Pi.S,
		},
	}
	regHnReqTime := time.Now().Sub(regHnReqStart)

	/// 3. send register commit with commit message
	regCpCommStart := time.Now()
	clientOsKeyPair, err := osign.GenerateClientKeys(serverOsPubKey)
	if err != nil {
		log.Fatal("Failed to generate client oblivious sign keys:", err)
		return nil
	}
	//
	encodedClientOsPubKey := osign.EncodeEcPoint(clientOsKeyPair.Q)
	jsonEncodedClientOsPubKey, err := json.Marshal(encodedClientOsPubKey)
	if err != nil {
		log.Fatal("Failed to encode client public key:", err)
		return nil
	}

	comRnd1 := GenerateRandomness()
	commit1 := sha256.New()
	commit1.Write([]byte(uid))
	commit1.Write([]byte(afId))
	commit1.Write([]byte(chResp.Challenge))
	commit1.Write(jsonEncodedClientOsPubKey)
	commit1.Write(comRnd1)
	com1 := commit1.Sum(nil)

	clientOsState, osignCom := osign.ClientSign1()
	reqCpCommTime := time.Now().Sub(regCpCommStart)

	reqHnCommStart := time.Now()
	param3 := &hn.ClientRegisterCommitRequest{
		Supi:        supi,
		CommitUID:   hex.EncodeToString(com1),
		CommitOsKey: hex.EncodeToString(*osignCom),
	}
	body, err := json.Marshal(param3)
	if err != nil {
		log.Fatal("Failed to marshal register commit request:", err)
		return nil
	}
	regResp, err = sendPostRequest(
		hnUrl,
		"/api/hn/reg/commit",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send register commit to HN:", err)
		return nil
	}
	var serverOsSignResp hnRegCommitResponse
	err = json.Unmarshal(regResp, &serverOsSignResp)
	if err != nil {
		log.Fatal("Failed to parse register commit response from HN:", err)
		return nil
	}
	reqHnCommTime := time.Now().Sub(reqHnCommStart)

	/// 4. send register finish
	reqCpSignStart := time.Now()
	comRnd2 := GenerateRandomness()
	commit2 := sha256.New()
	commit2.Write([]byte(afId))
	commit2.Write([]byte(chResp.Challenge))
	commit2.Write(comRnd2)
	com2 := commit2.Sum(nil)

	clientOsState, clientPreSign, err := osign.ClientSign2(
		com2,
		clientOsKeyPair,
		clientOsState,
		&osign.ServerPublicKey{
			Q: osign.ParseEcPoint(&serverOsSignResp.OsignPk),
			Pi: &osign.DlogProof{
				R: osign.ParseEcPoint(&serverOsSignResp.OsignPf.R),
				C: &serverOsSignResp.OsignPf.C,
				S: &serverOsSignResp.OsignPf.S,
			},
		})
	if err != nil {
		log.Fatal("Failed to client sign:", err)
		return nil
	}
	reqCpSignTime := time.Now().Sub(reqCpSignStart)

	reqHnFinStart := time.Now()
	param4 := &hn.ClientRegisterFinishRequest{
		Supi: supi,
		PreOsign: &osign.ApiClientPreSign{
			EncKey: clientPreSign.EncKey,
			M:      *clientPreSign.M,
			R:      *osign.EncodeEcPoint(clientPreSign.R),
			Pi: osign.ApiDLogProof{
				R: *osign.EncodeEcPoint(clientPreSign.Pi.R),
				C: *clientPreSign.Pi.C,
				S: *clientPreSign.Pi.S,
			},
			PailliarPubKey: *clientPreSign.PailliarPubKey,
		},
	}
	body, err = json.Marshal(param4)
	if err != nil {
		log.Fatal("Failed to marshal register finish request:", err)
		return nil
	}
	regResp, err = sendPostRequest(
		hnUrl,
		"/api/hn/reg/finish",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send register finish to HN:", err)
		return nil
	}
	var regFinishResp hnRegFinishResponse
	err = json.Unmarshal(regResp, &regFinishResp)
	if err != nil {
		log.Fatal("Failed to parse register finish response from HN:", err)
		return nil
	}
	reqHnFinTime := time.Now().Sub(reqHnFinStart)

	reqCpFinStart := time.Now()
	cipherBytes, err := hex.DecodeString(regFinishResp.Cipher)
	if err != nil {
		log.Fatal("Failed to decode cipher text:", err)
		return nil
	}
	serverPreSign := &osign.ServerPreSign{
		Ct: cipherBytes,
	}
	regSig, err := osign.ClientFinal(clientOsState, serverPreSign)
	if err != nil {
		log.Fatal("Failed to sign the message:", err)
		return nil
	}
	reqCpFinTime := time.Now().Sub(reqCpFinStart)

	/// 5. send register signature to AF
	reqAfFinStart := time.Now()
	param5 := &af.UserRegisterFinishRequest{
		Uid:         uid,
		SignatureHn: &serverOsSignResp.UidSignature,
		SignatureOs: regSig,
		UserVfKey:   encodedClientOsPubKey,
		Rnd1:        hex.EncodeToString(comRnd1),
		Rnd2:        hex.EncodeToString(comRnd2),
	}
	body, err = json.Marshal(param5)
	if err != nil {
		log.Fatal("Failed to marshal register finish request to AF:", err)
		return nil
	}
	regResp, err = sendPostRequest(
		afUrl,
		"/api/af/reg/finish",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send register finish to AF:", err)
		return nil
	}
	var afRegFinishResp afRegFinishResponse
	err = json.Unmarshal(regResp, &afRegFinishResp)
	if err != nil {
		log.Fatal("Failed to parse register finish response from AF:", err)
		return nil
	}
	reqAfFinTime := time.Now().Sub(reqAfFinStart)
	fmt.Println("Registration successful ? :", afRegFinishResp.Message)

	// stage 2: login test
	/// 1. request a challenge from AF
	loginAfReqStart := time.Now()
	param1 = make(map[string]string)
	param1["uid"] = uid
	loginAfResp, err := sendGetRequest(
		afUrl,
		"/api/af/login/request",
		param1,
		client)
	if err != nil {
		log.Fatal("Failed to send login request to AF:", err)
		return nil
	}
	var afLoginResp afLoginRequestResponse
	err = json.Unmarshal(loginAfResp, &afLoginResp)
	if err != nil {
		log.Fatal("Failed to parse login response from AF:", err)
		return nil
	}
	loginAfReqTime := time.Now().Sub(loginAfReqStart)

	/// 2. start the oblivious sign with HN
	loginCpCommStart := time.Now()
	loginClientState, loginClientComm := osign.ClientSign1()
	loginParam1 := &hn.ClientLoginRequest{
		Supi:   supi,
		Commit: hex.EncodeToString(*loginClientComm),
	}
	loginCpCommTime := time.Now().Sub(loginCpCommStart)

	loginHnReqStart := time.Now()
	body, err = json.Marshal(loginParam1)
	if err != nil {
		log.Fatal("Failed to marshal login request to HN:", err)
		return nil
	}
	loginHnResp, err := sendPostRequest(
		hnUrl,
		"/api/hn/login/request",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send login request to HN:", err)
		return nil
	}
	/// 3. continue the oblivious sign with HN
	var hnLoginResp hnLoginRequestResponse
	err = json.Unmarshal(loginHnResp, &hnLoginResp)
	if err != nil {
		log.Fatal("Failed to parse login response from HN:", err)
		return nil
	}
	loginHnReqTime := time.Now().Sub(loginHnReqStart)

	loginCpSignStart := time.Now()
	loginComRnd := GenerateRandomness()
	loginCommit := sha256.New()
	loginCommit.Write([]byte(afId))
	loginCommit.Write([]byte(afLoginResp.Challenge))
	loginCommit.Write(loginComRnd)
	loginCom := loginCommit.Sum(nil)

	loginClientState, loginClientPreSign, err := osign.ClientSign2(
		loginCom,
		clientOsKeyPair, // client key pair in register phase
		loginClientState,
		&osign.ServerPublicKey{
			Q: osign.ParseEcPoint(&hnLoginResp.OsignTpk),
			Pi: &osign.DlogProof{
				R: osign.ParseEcPoint(&hnLoginResp.OsignTpf.R),
				C: &hnLoginResp.OsignTpf.C,
				S: &hnLoginResp.OsignTpf.S,
			},
		})
	if err != nil {
		log.Fatal("Failed to client sign:", err)
		return nil
	}
	loginCpSignTime := time.Now().Sub(loginCpSignStart)

	loginHnFinStart := time.Now()
	loginParam2 := &hn.ClientLoginFinishRequest{
		Supi: supi,
		PreOsign: &osign.ApiClientPreSign{
			EncKey: loginClientPreSign.EncKey,
			M:      *loginClientPreSign.M,
			R:      *osign.EncodeEcPoint(loginClientPreSign.R),
			Pi: osign.ApiDLogProof{
				R: *osign.EncodeEcPoint(loginClientPreSign.Pi.R),
				C: *loginClientPreSign.Pi.C,
				S: *loginClientPreSign.Pi.S,
			},
			PailliarPubKey: *loginClientPreSign.PailliarPubKey,
		},
	}
	body, err = json.Marshal(loginParam2)
	if err != nil {
		log.Fatal("Failed to marshal login finish request to HN:", err)
		return nil
	}
	loginHnResp, err = sendPostRequest(
		hnUrl,
		"/api/hn/login/finish",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send login finish to HN:", err)
		return nil
	}

	var hnLoginFinishResp hnLoginFinishResponse
	err = json.Unmarshal(loginHnResp, &hnLoginFinishResp)
	if err != nil {
		log.Fatal("Failed to parse login finish response from HN:", err)
		return nil
	}
	loginHnFinTime := time.Now().Sub(loginHnFinStart)

	loginCpFinStart := time.Now()
	loginCipherBytes, err := hex.DecodeString(hnLoginFinishResp.Cipher)
	if err != nil {
		log.Fatal("Failed to decode cipher text:", err)
		return nil
	}
	loginServerPreSign := &osign.ServerPreSign{
		Ct: loginCipherBytes,
	}
	loginSig, err := osign.ClientFinal(loginClientState, loginServerPreSign)
	if err != nil {
		log.Fatal("Failed to sign the message:", err)
		return nil
	}
	loginCpFinTime := time.Now().Sub(loginCpFinStart)

	/// 4. extract the signature and finish with AF
	loginAfFinStart := time.Now()
	loginParam3 := &af.UserLoginFinishRequest{
		Uid:         uid,
		SignatureOs: loginSig,
		Rnd:         hex.EncodeToString(loginComRnd),
	}
	body, err = json.Marshal(loginParam3)
	if err != nil {
		log.Fatal("Failed to marshal login finish request to AF:", err)
		return nil
	}
	loginAfResp, err = sendPostRequest(
		afUrl,
		"/api/af/login/finish",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send login finish to AF:", err)
		return nil
	}
	var afLoginFinishResp afLoginFinishResponse
	err = json.Unmarshal(loginAfResp, &afLoginFinishResp)
	if err != nil {
		log.Fatal("Failed to parse login finish response from AF:", err)
		return nil
	}
	loginAfFinTime := time.Now().Sub(loginAfFinStart)
	fmt.Println("Login successful ? :", afLoginFinishResp.Message)

	stat := &AkmaProtocolBenchmarkStat{
		NwRegAFReqTime:   regAfReqTime,
		NwRegHNReqTime:   regHnReqTime,
		NwRegHNComTime:   reqHnCommTime,
		NwRegHNFinTime:   reqHnFinTime,
		NwRegAFFinTime:   reqAfFinTime,
		CpRegComTime:     reqCpCommTime,
		CpRegSignTime:    reqCpSignTime,
		CpRegFinTime:     reqCpFinTime,
		NwLoginAfReqTime: loginAfReqTime,
		NwLoginHNReqTime: loginHnReqTime,
		NwLoginHNFinTime: loginHnFinTime,
		NwLoginAFFinTime: loginAfFinTime,
		CpLoginComTime:   loginCpCommTime,
		CpLoginSignTime:  loginCpSignTime,
		CpLoginFinTime:   loginCpFinTime,
		// total time
		RegComputationTime:   reqCpCommTime + reqCpSignTime + reqCpFinTime,
		RegNetworkTime:       regAfReqTime + regHnReqTime + reqHnCommTime + reqHnFinTime + reqAfFinTime,
		RegTotalTime:         regAfReqTime + regHnReqTime + reqHnCommTime + reqHnFinTime + reqAfFinTime + reqCpCommTime + reqCpSignTime + reqCpFinTime,
		LoginComputationTime: loginCpCommTime + loginCpSignTime + loginCpFinTime,
		LoginNetworkTime:     loginAfReqTime + loginHnReqTime + loginHnFinTime + loginAfFinTime,
		LoginTotalTime:       loginAfReqTime + loginHnReqTime + loginHnFinTime + loginAfFinTime + loginCpCommTime + loginCpSignTime + loginCpFinTime,
	}

	return stat
}

func RunBenchmark2POS(n int) string {
	stat := make([]*ObliviousSignClientBenchmarkStat, n)
	for i := 0; i < n; i++ {
		stat[i] = benchmark2POSignature()
	}
	// compute the average time of each items
	var avgStat ObliviousSignClientBenchmarkStat
	for i := 0; i < n; i++ {
		avgStat.KeyGenTime += stat[i].KeyGenTime
		avgStat.Sign1Time += stat[i].Sign1Time
		avgStat.Sign2Time += stat[i].Sign2Time
		avgStat.Sign3Time += stat[i].Sign3Time
		avgStat.TotalClientTime += stat[i].TotalClientTime
	}
	avgStat.KeyGenTime /= time.Duration(n)
	avgStat.Sign1Time /= time.Duration(n)
	avgStat.Sign2Time /= time.Duration(n)
	avgStat.Sign3Time /= time.Duration(n)
	avgStat.TotalClientTime /= time.Duration(n)
	// format the result as readable string
	res := fmt.Sprintf("[Benchmark 2PO Signature (run %d times)]\n", n)
	res += fmt.Sprintf("KeyGenTime: %v\n", avgStat.KeyGenTime)
	res += fmt.Sprintf("Sign1Time: %v\n", avgStat.Sign1Time)
	res += fmt.Sprintf("Sign2Time: %v\n", avgStat.Sign2Time)
	res += fmt.Sprintf("Sign3Time: %v\n", avgStat.Sign3Time)
	res += fmt.Sprintf("TotalClientTime: %v\n", avgStat.TotalClientTime)
	res += fmt.Sprintf("[Finish At: %v]\n", time.Now().Format("2006-01-02 15:04:05"))

	return fmt.Sprintf(res)
}

func RunBenchmarkProtocol(n int, hnUrl, afUrl string) string {
	stat := make([]*AkmaProtocolBenchmarkStat, n)
	for i := 0; i < n; i++ {
		stat[i] = benchmarkAKMA(hnUrl, afUrl)
	}
	// compute the average time of each items
	var avgStat AkmaProtocolBenchmarkStat
	for i := 0; i < n; i++ {
		avgStat.NwRegAFReqTime += stat[i].NwRegAFReqTime
		avgStat.NwRegHNReqTime += stat[i].NwRegHNReqTime
		avgStat.NwRegHNComTime += stat[i].NwRegHNComTime
		avgStat.NwRegHNFinTime += stat[i].NwRegHNFinTime
		avgStat.NwRegAFFinTime += stat[i].NwRegAFFinTime
		avgStat.CpRegComTime += stat[i].CpRegComTime
		avgStat.CpRegSignTime += stat[i].CpRegSignTime
		avgStat.CpRegFinTime += stat[i].CpRegFinTime
		avgStat.NwLoginAfReqTime += stat[i].NwLoginAfReqTime
		avgStat.NwLoginHNReqTime += stat[i].NwLoginHNReqTime
		avgStat.NwLoginHNFinTime += stat[i].NwLoginHNFinTime
		avgStat.NwLoginAFFinTime += stat[i].NwLoginAFFinTime
		avgStat.CpLoginComTime += stat[i].CpLoginComTime
		avgStat.CpLoginSignTime += stat[i].CpLoginSignTime
		avgStat.CpLoginFinTime += stat[i].CpLoginFinTime
		avgStat.RegComputationTime += stat[i].RegComputationTime
		avgStat.RegNetworkTime += stat[i].RegNetworkTime
		avgStat.RegTotalTime += stat[i].RegTotalTime
		avgStat.LoginComputationTime += stat[i].LoginComputationTime
		avgStat.LoginNetworkTime += stat[i].LoginNetworkTime
		avgStat.LoginTotalTime += stat[i].LoginTotalTime
	}
	avgStat.NwRegAFReqTime /= time.Duration(n)
	avgStat.NwRegHNReqTime /= time.Duration(n)
	avgStat.NwRegHNComTime /= time.Duration(n)
	avgStat.NwRegHNFinTime /= time.Duration(n)
	avgStat.NwRegAFFinTime /= time.Duration(n)
	avgStat.CpRegComTime /= time.Duration(n)
	avgStat.CpRegSignTime /= time.Duration(n)
	avgStat.CpRegFinTime /= time.Duration(n)
	avgStat.NwLoginAfReqTime /= time.Duration(n)
	avgStat.NwLoginHNReqTime /= time.Duration(n)
	avgStat.NwLoginHNFinTime /= time.Duration(n)
	avgStat.NwLoginAFFinTime /= time.Duration(n)
	avgStat.CpLoginComTime /= time.Duration(n)
	avgStat.CpLoginSignTime /= time.Duration(n)
	avgStat.CpLoginFinTime /= time.Duration(n)
	avgStat.RegComputationTime /= time.Duration(n)
	avgStat.RegNetworkTime /= time.Duration(n)
	avgStat.RegTotalTime /= time.Duration(n)
	avgStat.LoginComputationTime /= time.Duration(n)
	avgStat.LoginNetworkTime /= time.Duration(n)
	avgStat.LoginTotalTime /= time.Duration(n)

	// fomat the result as readable string
	res := fmt.Sprintf("[Benchmark AKMA Protocol (run %d times)]\n", n)
	res += fmt.Sprintf("[[=== Register ===]]\n")
	res += fmt.Sprintf("(net)Request AF Challenge Time: %v\n", avgStat.NwRegAFReqTime)
	res += fmt.Sprintf("(net)Request HN 2POS Keygen Time: %v\n", avgStat.NwRegHNReqTime)
	res += fmt.Sprintf("(net)2POS Commit to HN Time: %v\n", avgStat.NwRegHNComTime)
	res += fmt.Sprintf("(net)2POS Finish to HN Time: %v\n", avgStat.NwRegHNFinTime)
	res += fmt.Sprintf("(net)Finish to AF Time: %v\n", avgStat.NwRegAFFinTime)
	res += fmt.Sprintf("(comp)Client 2POS Commit Time: %v\n", avgStat.CpRegComTime)
	res += fmt.Sprintf("(comp)Client 2POS Sign Time: %v\n", avgStat.CpRegSignTime)
	res += fmt.Sprintf("(comp)Client 2POS Finish Time: %v\n", avgStat.CpRegFinTime)
	res += fmt.Sprintf("[[=== Login ===]]\n")
	res += fmt.Sprintf("(net)Request AF Challenge Time: %v\n", avgStat.NwLoginAfReqTime)
	res += fmt.Sprintf("(net)Request HN 2POS Time: %v\n", avgStat.NwLoginHNReqTime)
	res += fmt.Sprintf("(net)Finish 2POS with HN Time: %v\n", avgStat.NwLoginHNFinTime)
	res += fmt.Sprintf("(net)Finish with AF Time: %v\n", avgStat.NwLoginAFFinTime)
	res += fmt.Sprintf("(comp)Client 2POS Commit Time: %v\n", avgStat.CpLoginComTime)
	res += fmt.Sprintf("(comp)Client 2POS Sign Time: %v\n", avgStat.CpLoginSignTime)
	res += fmt.Sprintf("(comp)Client 2POS Finish Time: %v\n", avgStat.CpLoginFinTime)
	res += fmt.Sprintf("[[=== Total ===]]\n")
	res += fmt.Sprintf("Register Computation Time: %v\n", avgStat.RegComputationTime)
	res += fmt.Sprintf("Register Network Time: %v\n", avgStat.RegNetworkTime)
	res += fmt.Sprintf("Register Total Time: %v\n", avgStat.RegTotalTime)
	res += fmt.Sprintf("Login Computation Time: %v\n", avgStat.LoginComputationTime)
	res += fmt.Sprintf("Login Network Time: %v\n", avgStat.LoginNetworkTime)
	res += fmt.Sprintf("Login Total Time: %v\n", avgStat.LoginTotalTime)
	res += fmt.Sprintf("---------------\n")
	res += fmt.Sprintf("[Finish At: %v]\n", time.Now().Format("2006-01-02 15:04:05"))
	return fmt.Sprintf(res)
}

/**
 * add new benchmark function for amortized 2POS.
 */

func benchmarkAmortized2POSignature() *ObliviousSignClientBenchmarkStat {
	/// 1. Benchmark the Oblivious Sign
	var obsignStat ObliviousSignClientBenchmarkStat
	//server gen:
	// set timer:
	skeygen_start := time.Now()
	serverKey := osign.GenerateServerKeys()
	skeygen_end := time.Now()
	fmt.Printf(">>> server key gen time: %v\n", skeygen_end.Sub(skeygen_start))

	// client gen:
	// set timer
	ckeygen_start := time.Now()
	clientKey, _ := osign.GenerateClientKeys(serverKey.PubKey)
	ckeygen_end := time.Now()

	fmt.Printf(">>> client key gen time: %v\n", ckeygen_end.Sub(ckeygen_start))
	obsignStat.KeyGenTime = ckeygen_end.Sub(ckeygen_start)

	// compute the vk in server side:
	vk := serverKey.PubKey.Q.ScalarMul(clientKey.X)

	// pre-computation
	preClientInfo, err := osign.PrecomputeClientSign(clientKey)
	if err != nil {
		log.Fatal("Failed to precompute client sign:", err)
		return nil
	}
	preServerInfo := osign.PrecomputeServerSign(serverKey.PrivKey)

	// round 1
	// set timer
	csign1_start := time.Now()
	clientState, comm := osign.AmortizedClientSign1(preClientInfo)
	csign1_end := time.Now()
	fmt.Printf(">>> [Amorized] client sign1 time: %v\n", csign1_end.Sub(csign1_start))
	obsignStat.Sign1Time = csign1_end.Sub(csign1_start)

	//
	// set timer
	ssign1_start := time.Now()
	serverState, serverOsPk := osign.AmortizedServerSign1(*comm, preServerInfo)
	ssign1_end := time.Now()
	fmt.Printf(">>> [Amorized] server sign1 time: %v\n", ssign1_end.Sub(ssign1_start))

	// round 2
	message := []byte("test message")
	mhash := bigint.HashBytesToBigInt(message)

	// set timer
	csign2_start := time.Now()
	clientState, clientPreSign, _ := osign.AmortizedClientSign2(message, clientKey, clientState, serverOsPk, preClientInfo)
	csign2_end := time.Now()
	fmt.Printf(">>> [Amorized] client sign2 time: %v\n", csign2_end.Sub(csign2_start))
	obsignStat.Sign2Time = csign2_end.Sub(csign2_start)

	//
	// set timer
	ssign2_start := time.Now()
	serverPreSign, _ := osign.AmortizedServerSign2(serverKey.PrivKey, serverState, clientPreSign, preServerInfo)
	ssign2_end := time.Now()
	fmt.Printf(">>> [Amorized] server sign2 time: %v\n", ssign2_end.Sub(ssign2_start))

	// final
	// set timer
	cfinal_start := time.Now()
	outSig, _ := osign.ClientFinal(clientState, serverPreSign)
	cfinal_end := time.Now()
	fmt.Printf(">>> client final time: %v\n", cfinal_end.Sub(cfinal_start))
	obsignStat.Sign3Time = cfinal_end.Sub(cfinal_start)

	// verify the signature
	// set timer
	verf_start := time.Now()
	verfied_ := ecdsa.Verify(vk, mhash, outSig, secp256k1.GetSecp256k1())
	verf_end := time.Now()
	fmt.Printf(">>> verifying (ecdsa) time: %v\n", verf_end.Sub(verf_start))
	fmt.Printf("verifing signature result - verified: %t\n", verfied_)

	obsignStat.TotalClientTime = obsignStat.KeyGenTime + obsignStat.Sign1Time + obsignStat.Sign2Time + obsignStat.Sign3Time
	return &obsignStat
}

func benchmarkAmortizedAKMA(hnUrl, afUrl string) *AkmaProtocolBenchmarkStat {
	// generate a random user
	afId := "AppFunction@b53ca8af879f65"
	uid := GenerateUID()
	username := "U-" + uid
	supi := "imsi-" + GenerateSUPI()

	// stage 1: register
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := &http.Client{
		Timeout:   time.Minute,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	/// 1. send register request to AF
	regAfReqStart := time.Now()
	param1 := make(map[string]string)
	param1["uid"] = uid
	param1["username"] = username
	regResp, err := sendGetRequest(
		afUrl,
		"/api/af/reg/request",
		param1,
		client)
	if err != nil {
		log.Fatal("Failed to send register request to AF:", err)
		return nil
	}
	//parse the challenge from AF's response
	var chResp afRegRequestResponse
	err = json.Unmarshal(regResp, &chResp)
	if err != nil {
		log.Fatal("Failed to parse register response from AF:", err)
		return nil
	}
	regAfReqTime := time.Now().Sub(regAfReqStart)
	/// 2. send register request to HN
	regHnReqStart := time.Now()
	param2 := make(map[string]string)
	param2["supi"] = supi
	regResp, err = sendGetRequest(
		hnUrl,
		"/api/hn/reg/request",
		param2,
		client)
	if err != nil {
		log.Fatal("Failed to send register request to HN:", err)
		return nil
	}
	var serverOsKeyResp hnRegRequestResponse
	err = json.Unmarshal(regResp, &serverOsKeyResp)
	if err != nil {
		log.Fatal("Failed to parse register response from HN:", err)
		return nil
	}
	serverOsPubKey := &osign.ServerPublicKey{
		Q: osign.ParseEcPoint(&serverOsKeyResp.PublicKey.Q),
		Pi: &osign.DlogProof{
			R: osign.ParseEcPoint(&serverOsKeyResp.PublicKey.Pi.R),
			C: &serverOsKeyResp.PublicKey.Pi.C,
			S: &serverOsKeyResp.PublicKey.Pi.S,
		},
	}
	regHnReqTime := time.Now().Sub(regHnReqStart)

	/// amortized prepare client keys for pre-computation
	clientOsKeyPair, err := osign.GenerateClientKeys(serverOsPubKey)
	if err != nil {
		log.Fatal("Failed to generate client oblivious sign keys:", err)
		return nil
	}
	preComputedInfo4Reg, err := osign.PrecomputeClientSign(clientOsKeyPair)
	if err != nil {
		log.Fatal("Failed to precompute client sign in register:", err)
		return nil
	}
	preComputedInfo4Login, err := osign.PrecomputeClientSign(clientOsKeyPair)
	if err != nil {
		log.Fatal("Failed to precompute client sign in login:", err)
		return nil
	}

	/// 3. send register commit with commit message
	regCpCommStart := time.Now()
	//
	encodedClientOsPubKey := osign.EncodeEcPoint(clientOsKeyPair.Q)
	jsonEncodedClientOsPubKey, err := json.Marshal(encodedClientOsPubKey)
	if err != nil {
		log.Fatal("Failed to encode client public key:", err)
		return nil
	}

	comRnd1 := GenerateRandomness()
	commit1 := sha256.New()
	commit1.Write([]byte(uid))
	commit1.Write([]byte(afId))
	commit1.Write([]byte(chResp.Challenge))
	commit1.Write(jsonEncodedClientOsPubKey)
	commit1.Write(comRnd1)
	com1 := commit1.Sum(nil)

	clientOsState, osignCom := osign.AmortizedClientSign1(preComputedInfo4Reg)
	reqCpCommTime := time.Now().Sub(regCpCommStart)

	reqHnCommStart := time.Now()
	param3 := &hn.ClientRegisterCommitRequest{
		Supi:        supi,
		CommitUID:   hex.EncodeToString(com1),
		CommitOsKey: hex.EncodeToString(*osignCom),
	}
	body, err := json.Marshal(param3)
	if err != nil {
		log.Fatal("Failed to marshal register commit request:", err)
		return nil
	}
	regResp, err = sendPostRequest(
		hnUrl,
		"/api/hn/reg/commit",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send register commit to HN:", err)
		return nil
	}
	var serverOsSignResp hnRegCommitResponse
	err = json.Unmarshal(regResp, &serverOsSignResp)
	if err != nil {
		log.Fatal("Failed to parse register commit response from HN:", err)
		return nil
	}
	reqHnCommTime := time.Now().Sub(reqHnCommStart)

	/// 4. send register finish
	reqCpSignStart := time.Now()
	comRnd2 := GenerateRandomness()
	commit2 := sha256.New()
	commit2.Write([]byte(afId))
	commit2.Write([]byte(chResp.Challenge))
	commit2.Write(comRnd2)
	com2 := commit2.Sum(nil)

	clientOsState, clientPreSign, err := osign.AmortizedClientSign2(
		com2,
		clientOsKeyPair,
		clientOsState,
		&osign.ServerPublicKey{
			Q: osign.ParseEcPoint(&serverOsSignResp.OsignPk),
			Pi: &osign.DlogProof{
				R: osign.ParseEcPoint(&serverOsSignResp.OsignPf.R),
				C: &serverOsSignResp.OsignPf.C,
				S: &serverOsSignResp.OsignPf.S,
			},
		},
		preComputedInfo4Reg)
	if err != nil {
		log.Fatal("Failed to client sign:", err)
		return nil
	}
	reqCpSignTime := time.Now().Sub(reqCpSignStart)

	reqHnFinStart := time.Now()
	param4 := &hn.ClientRegisterFinishRequest{
		Supi: supi,
		PreOsign: &osign.ApiClientPreSign{
			EncKey: clientPreSign.EncKey,
			M:      *clientPreSign.M,
			R:      *osign.EncodeEcPoint(clientPreSign.R),
			Pi: osign.ApiDLogProof{
				R: *osign.EncodeEcPoint(clientPreSign.Pi.R),
				C: *clientPreSign.Pi.C,
				S: *clientPreSign.Pi.S,
			},
			PailliarPubKey: *clientPreSign.PailliarPubKey,
		},
	}
	body, err = json.Marshal(param4)
	if err != nil {
		log.Fatal("Failed to marshal register finish request:", err)
		return nil
	}
	regResp, err = sendPostRequest(
		hnUrl,
		"/api/hn/reg/finish",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send register finish to HN:", err)
		return nil
	}
	var regFinishResp hnRegFinishResponse
	err = json.Unmarshal(regResp, &regFinishResp)
	if err != nil {
		log.Fatal("Failed to parse register finish response from HN:", err)
		return nil
	}
	reqHnFinTime := time.Now().Sub(reqHnFinStart)

	reqCpFinStart := time.Now()
	cipherBytes, err := hex.DecodeString(regFinishResp.Cipher)
	if err != nil {
		log.Fatal("Failed to decode cipher text:", err)
		return nil
	}
	serverPreSign := &osign.ServerPreSign{
		Ct: cipherBytes,
	}
	regSig, err := osign.ClientFinal(clientOsState, serverPreSign)
	if err != nil {
		log.Fatal("Failed to sign the message:", err)
		return nil
	}
	reqCpFinTime := time.Now().Sub(reqCpFinStart)

	/// 5. send register signature to AF
	reqAfFinStart := time.Now()
	param5 := &af.UserRegisterFinishRequest{
		Uid:         uid,
		SignatureHn: &serverOsSignResp.UidSignature,
		SignatureOs: regSig,
		UserVfKey:   encodedClientOsPubKey,
		Rnd1:        hex.EncodeToString(comRnd1),
		Rnd2:        hex.EncodeToString(comRnd2),
	}
	body, err = json.Marshal(param5)
	if err != nil {
		log.Fatal("Failed to marshal register finish request to AF:", err)
		return nil
	}
	regResp, err = sendPostRequest(
		afUrl,
		"/api/af/reg/finish",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send register finish to AF:", err)
		return nil
	}
	var afRegFinishResp afRegFinishResponse
	err = json.Unmarshal(regResp, &afRegFinishResp)
	if err != nil {
		log.Fatal("Failed to parse register finish response from AF:", err)
		return nil
	}
	reqAfFinTime := time.Now().Sub(reqAfFinStart)
	fmt.Println("Registration successful ? :", afRegFinishResp.Message)

	// stage 2: login test
	/// 1. request a challenge from AF
	loginAfReqStart := time.Now()
	param1 = make(map[string]string)
	param1["uid"] = uid
	loginAfResp, err := sendGetRequest(
		afUrl,
		"/api/af/login/request",
		param1,
		client)
	if err != nil {
		log.Fatal("Failed to send login request to AF:", err)
		return nil
	}
	var afLoginResp afLoginRequestResponse
	err = json.Unmarshal(loginAfResp, &afLoginResp)
	if err != nil {
		log.Fatal("Failed to parse login response from AF:", err)
		return nil
	}
	loginAfReqTime := time.Now().Sub(loginAfReqStart)

	/// 2. start the oblivious sign with HN
	loginCpCommStart := time.Now()
	loginClientState, loginClientComm := osign.AmortizedClientSign1(preComputedInfo4Login)
	loginParam1 := &hn.ClientLoginRequest{
		Supi:   supi,
		Commit: hex.EncodeToString(*loginClientComm),
	}
	loginCpCommTime := time.Now().Sub(loginCpCommStart)

	loginHnReqStart := time.Now()
	body, err = json.Marshal(loginParam1)
	if err != nil {
		log.Fatal("Failed to marshal login request to HN:", err)
		return nil
	}
	loginHnResp, err := sendPostRequest(
		hnUrl,
		"/api/hn/login/request",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send login request to HN:", err)
		return nil
	}
	/// 3. continue the oblivious sign with HN
	var hnLoginResp hnLoginRequestResponse
	err = json.Unmarshal(loginHnResp, &hnLoginResp)
	if err != nil {
		log.Fatal("Failed to parse login response from HN:", err)
		return nil
	}
	loginHnReqTime := time.Now().Sub(loginHnReqStart)

	loginCpSignStart := time.Now()
	loginComRnd := GenerateRandomness()
	loginCommit := sha256.New()
	loginCommit.Write([]byte(afId))
	loginCommit.Write([]byte(afLoginResp.Challenge))
	loginCommit.Write(loginComRnd)
	loginCom := loginCommit.Sum(nil)

	loginClientState, loginClientPreSign, err := osign.AmortizedClientSign2(
		loginCom,
		clientOsKeyPair, // client key pair in register phase
		loginClientState,
		&osign.ServerPublicKey{
			Q: osign.ParseEcPoint(&hnLoginResp.OsignTpk),
			Pi: &osign.DlogProof{
				R: osign.ParseEcPoint(&hnLoginResp.OsignTpf.R),
				C: &hnLoginResp.OsignTpf.C,
				S: &hnLoginResp.OsignTpf.S,
			},
		},
		preComputedInfo4Login)
	if err != nil {
		log.Fatal("Failed to client sign:", err)
		return nil
	}
	loginCpSignTime := time.Now().Sub(loginCpSignStart)

	loginHnFinStart := time.Now()
	loginParam2 := &hn.ClientLoginFinishRequest{
		Supi: supi,
		PreOsign: &osign.ApiClientPreSign{
			EncKey: loginClientPreSign.EncKey,
			M:      *loginClientPreSign.M,
			R:      *osign.EncodeEcPoint(loginClientPreSign.R),
			Pi: osign.ApiDLogProof{
				R: *osign.EncodeEcPoint(loginClientPreSign.Pi.R),
				C: *loginClientPreSign.Pi.C,
				S: *loginClientPreSign.Pi.S,
			},
			PailliarPubKey: *loginClientPreSign.PailliarPubKey,
		},
	}
	body, err = json.Marshal(loginParam2)
	if err != nil {
		log.Fatal("Failed to marshal login finish request to HN:", err)
		return nil
	}
	loginHnResp, err = sendPostRequest(
		hnUrl,
		"/api/hn/login/finish",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send login finish to HN:", err)
		return nil
	}

	var hnLoginFinishResp hnLoginFinishResponse
	err = json.Unmarshal(loginHnResp, &hnLoginFinishResp)
	if err != nil {
		log.Fatal("Failed to parse login finish response from HN:", err)
		return nil
	}
	loginHnFinTime := time.Now().Sub(loginHnFinStart)

	loginCpFinStart := time.Now()
	loginCipherBytes, err := hex.DecodeString(hnLoginFinishResp.Cipher)
	if err != nil {
		log.Fatal("Failed to decode cipher text:", err)
		return nil
	}
	loginServerPreSign := &osign.ServerPreSign{
		Ct: loginCipherBytes,
	}
	loginSig, err := osign.ClientFinal(loginClientState, loginServerPreSign)
	if err != nil {
		log.Fatal("Failed to sign the message:", err)
		return nil
	}
	loginCpFinTime := time.Now().Sub(loginCpFinStart)

	/// 4. extract the signature and finish with AF
	loginAfFinStart := time.Now()
	loginParam3 := &af.UserLoginFinishRequest{
		Uid:         uid,
		SignatureOs: loginSig,
		Rnd:         hex.EncodeToString(loginComRnd),
	}
	body, err = json.Marshal(loginParam3)
	if err != nil {
		log.Fatal("Failed to marshal login finish request to AF:", err)
		return nil
	}
	loginAfResp, err = sendPostRequest(
		afUrl,
		"/api/af/login/finish",
		body,
		client)
	if err != nil {
		log.Fatal("Failed to send login finish to AF:", err)
		return nil
	}
	var afLoginFinishResp afLoginFinishResponse
	err = json.Unmarshal(loginAfResp, &afLoginFinishResp)
	if err != nil {
		log.Fatal("Failed to parse login finish response from AF:", err)
		return nil
	}
	loginAfFinTime := time.Now().Sub(loginAfFinStart)
	fmt.Println("Login successful ? :", afLoginFinishResp.Message)

	stat := &AkmaProtocolBenchmarkStat{
		NwRegAFReqTime:   regAfReqTime,
		NwRegHNReqTime:   regHnReqTime,
		NwRegHNComTime:   reqHnCommTime,
		NwRegHNFinTime:   reqHnFinTime,
		NwRegAFFinTime:   reqAfFinTime,
		CpRegComTime:     reqCpCommTime,
		CpRegSignTime:    reqCpSignTime,
		CpRegFinTime:     reqCpFinTime,
		NwLoginAfReqTime: loginAfReqTime,
		NwLoginHNReqTime: loginHnReqTime,
		NwLoginHNFinTime: loginHnFinTime,
		NwLoginAFFinTime: loginAfFinTime,
		CpLoginComTime:   loginCpCommTime,
		CpLoginSignTime:  loginCpSignTime,
		CpLoginFinTime:   loginCpFinTime,
		// total time
		RegComputationTime:   reqCpCommTime + reqCpSignTime + reqCpFinTime,
		RegNetworkTime:       regAfReqTime + regHnReqTime + reqHnCommTime + reqHnFinTime + reqAfFinTime,
		RegTotalTime:         regAfReqTime + regHnReqTime + reqHnCommTime + reqHnFinTime + reqAfFinTime + reqCpCommTime + reqCpSignTime + reqCpFinTime,
		LoginComputationTime: loginCpCommTime + loginCpSignTime + loginCpFinTime,
		LoginNetworkTime:     loginAfReqTime + loginHnReqTime + loginHnFinTime + loginAfFinTime,
		LoginTotalTime:       loginAfReqTime + loginHnReqTime + loginHnFinTime + loginAfFinTime + loginCpCommTime + loginCpSignTime + loginCpFinTime,
	}

	return stat
}

type NormalAkmaProtocolBenchmarkStat struct {
	NwHNReqTime time.Duration `json:"nw_hn_req_time"`
	NwAFReqTime time.Duration `json:"nw_af_req_time"`
	NwAFFinTime time.Duration `json:"nw_af_fin_time"`
	CpHnReqTime time.Duration `json:"cp_hn_req_time"`
	CpAFReqTime time.Duration `json:"cp_af_req_time"`
	CpAFFinTime time.Duration `json:"cp_af_fin_time"`

	// total:
	ComputationTime time.Duration `json:"computation_time"`
	NetworkTime     time.Duration `json:"network_time"`
	TotalTime       time.Duration `json:"login_total_time"`
}

func benchmark5gAKMA(hnUrl, afUrl string) *NormalAkmaProtocolBenchmarkStat {
	// generate a random user
	afId := "AppFunction@b53ca8af879f65"
	//uid := GenerateUID()
	//username := "U-" + uid
	supi := "imsi-" + GenerateSUPI()

	// stage 1: register
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := &http.Client{
		Timeout:   time.Minute,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	/// 1. send register request to HN
	hnReqStart := time.Now()
	param1 := make(map[string]string)
	nc := GenerateRandomness()
	param1["supi"] = supi
	param1["nonce"] = hex.EncodeToString(nc)
	param1["afId"] = afId
	// convert param1 to json
	jsonBody1, err := json.Marshal(param1)
	if err != nil {
		log.Fatal("Failed to marshal register request to HN:", err)
		return nil
	}
	hnResp, err := sendPostRequest(
		hnUrl,
		"/api/hn/akma/uerequest",
		jsonBody1,
		client)
	if err != nil {
		log.Fatal("Failed to send register request to AF:", err)
		return nil
	}
	hnRespData := make(map[string]string)
	err = json.Unmarshal(hnResp, &hnRespData)
	if err != nil {
		log.Fatal("Failed to parse register response from HN:", err)
		return nil
	}
	hnReqTime := time.Now().Sub(hnReqStart)
	/// computation keys
	hnComputeStart := time.Now()
	K_ausf := hnRespData["key"]
	message1 := make([]byte, 0)
	message1 = append(message1, 0x80)
	message1 = append(message1, []byte("AKMA")...)
	message1 = append(message1, 0x00, 0x04)
	message1 = append(message1, []byte(supi)...)
	message1 = append(message1, 0x0f)

	h1 := hmac.New(sha256.New, []byte(K_ausf))
	h1.Write(message1)
	k_akma := h1.Sum(nil)

	message2 := make([]byte, 0)
	message2 = append(message2, 0x81)
	message2 = append(message2, []byte("A-TID")...)
	message2 = append(message2, 0x00, 0x05)
	message2 = append(message2, []byte(supi)...)
	message2 = append(message2, 0x0f)

	h2 := hmac.New(sha256.New, []byte(K_ausf))
	h2.Write(message2)
	atid := h2.Sum(nil)

	message3 := make([]byte, 0)
	message3 = append(message3, 0x82)
	message3 = append(message3, []byte(afId)...)
	message3 = append(message3, []byte(string(len(afId)))...)

	h3 := hmac.New(sha256.New, k_akma)
	h3.Write(message3)
	k_af := h3.Sum(nil)
	hnComputeTime := time.Now().Sub(hnComputeStart)

	/// 2. send request to AF
	afReqStart := time.Now()
	param2 := make(map[string]string)
	param2["supi"] = supi
	param2["atid"] = hex.EncodeToString(atid)
	param2["k_af"] = hex.EncodeToString(k_af)
	jsonBody2, err := json.Marshal(param2)
	if err != nil {
		log.Fatal("Failed to marshal register request to AF:", err)
		return nil
	}

	afResp, err := sendPostRequest(
		afUrl,
		"/api/af/akma/uerequest",
		jsonBody2,
		client)
	if err != nil {
		log.Fatal("Failed to send register request to AF:", err)
		return nil
	}
	afRespData := make(map[string]string)
	err = json.Unmarshal(afResp, &afRespData)
	if err != nil {
		log.Fatal("Failed to parse register response from AF:", err)
		return nil
	}
	afReqTime := time.Now().Sub(afReqStart)

	/// 3. send finish to AF
	afFinStart := time.Now()
	// compute the MAC with k_af
	h := hmac.New(sha256.New, []byte(k_af))
	h.Write([]byte(afId))
	h.Write([]byte(supi))
	h.Write([]byte(hex.EncodeToString(atid)))
	tag := h.Sum(nil)

	param3 := make(map[string]string)
	param3["supi"] = supi
	param3["tag"] = hex.EncodeToString(tag)
	jsonBody3, err := json.Marshal(param3)
	if err != nil {
		log.Fatal("Failed to marshal register finish request to AF:", err)
		return nil
	}
	afResp, err = sendPostRequest(
		afUrl,
		"/api/af/akma/uefinish",
		jsonBody3,
		client)
	if err != nil {
		log.Fatal("Failed to send register finish to AF:", err)
		return nil
	}
	afFinTime := time.Now().Sub(afFinStart)

	stat := &NormalAkmaProtocolBenchmarkStat{
		NwHNReqTime: hnReqTime,
		NwAFReqTime: afReqTime,
		NwAFFinTime: afFinTime,
		CpHnReqTime: hnComputeTime,
		//CpAFReqTime: afReqTime,
		//CpAFFinTime: afFinTime,
		ComputationTime: hnComputeTime,
		NetworkTime:     hnReqTime + afReqTime + afFinTime,
	}

	return stat
}

func RunBenchmarkAmortized2POS(n int) string {
	stat := make([]*ObliviousSignClientBenchmarkStat, n)
	for i := 0; i < n; i++ {
		stat[i] = benchmarkAmortized2POSignature()
	}
	// compute the average time of each items
	var avgStat ObliviousSignClientBenchmarkStat
	for i := 0; i < n; i++ {
		avgStat.KeyGenTime += stat[i].KeyGenTime
		avgStat.Sign1Time += stat[i].Sign1Time
		avgStat.Sign2Time += stat[i].Sign2Time
		avgStat.Sign3Time += stat[i].Sign3Time
		avgStat.TotalClientTime += stat[i].TotalClientTime
	}
	avgStat.KeyGenTime /= time.Duration(n)
	avgStat.Sign1Time /= time.Duration(n)
	avgStat.Sign2Time /= time.Duration(n)
	avgStat.Sign3Time /= time.Duration(n)
	avgStat.TotalClientTime /= time.Duration(n)
	// format the result as readable string
	res := fmt.Sprintf("[Benchmark Amorized 2PO Signature (run %d times)]\n", n)
	res += fmt.Sprintf("KeyGenTime: %v\n", avgStat.KeyGenTime)
	res += fmt.Sprintf("Amorized Sign1Time: %v\n", avgStat.Sign1Time)
	res += fmt.Sprintf("Amorized Sign2Time: %v\n", avgStat.Sign2Time)
	res += fmt.Sprintf("Sign3Time: %v\n", avgStat.Sign3Time)
	res += fmt.Sprintf("TotalClientTime: %v\n", avgStat.TotalClientTime)
	res += fmt.Sprintf("[Finish At: %v]\n", time.Now().Format("2006-01-02 15:04:05"))

	return fmt.Sprintf(res)
}

func RunBenchmarkAmortizedProtocol(n int, hnUrl, afUrl string) string {
	stat := make([]*AkmaProtocolBenchmarkStat, n)
	for i := 0; i < n; i++ {
		stat[i] = benchmarkAmortizedAKMA(hnUrl, afUrl)
	}
	// compute the average time of each items
	var avgStat AkmaProtocolBenchmarkStat
	for i := 0; i < n; i++ {
		avgStat.NwRegAFReqTime += stat[i].NwRegAFReqTime
		avgStat.NwRegHNReqTime += stat[i].NwRegHNReqTime
		avgStat.NwRegHNComTime += stat[i].NwRegHNComTime
		avgStat.NwRegHNFinTime += stat[i].NwRegHNFinTime
		avgStat.NwRegAFFinTime += stat[i].NwRegAFFinTime
		avgStat.CpRegComTime += stat[i].CpRegComTime
		avgStat.CpRegSignTime += stat[i].CpRegSignTime
		avgStat.CpRegFinTime += stat[i].CpRegFinTime
		avgStat.NwLoginAfReqTime += stat[i].NwLoginAfReqTime
		avgStat.NwLoginHNReqTime += stat[i].NwLoginHNReqTime
		avgStat.NwLoginHNFinTime += stat[i].NwLoginHNFinTime
		avgStat.NwLoginAFFinTime += stat[i].NwLoginAFFinTime
		avgStat.CpLoginComTime += stat[i].CpLoginComTime
		avgStat.CpLoginSignTime += stat[i].CpLoginSignTime
		avgStat.CpLoginFinTime += stat[i].CpLoginFinTime
		avgStat.RegComputationTime += stat[i].RegComputationTime
		avgStat.RegNetworkTime += stat[i].RegNetworkTime
		avgStat.RegTotalTime += stat[i].RegTotalTime
		avgStat.LoginComputationTime += stat[i].LoginComputationTime
		avgStat.LoginNetworkTime += stat[i].LoginNetworkTime
		avgStat.LoginTotalTime += stat[i].LoginTotalTime
	}
	avgStat.NwRegAFReqTime /= time.Duration(n)
	avgStat.NwRegHNReqTime /= time.Duration(n)
	avgStat.NwRegHNComTime /= time.Duration(n)
	avgStat.NwRegHNFinTime /= time.Duration(n)
	avgStat.NwRegAFFinTime /= time.Duration(n)
	avgStat.CpRegComTime /= time.Duration(n)
	avgStat.CpRegSignTime /= time.Duration(n)
	avgStat.CpRegFinTime /= time.Duration(n)
	avgStat.NwLoginAfReqTime /= time.Duration(n)
	avgStat.NwLoginHNReqTime /= time.Duration(n)
	avgStat.NwLoginHNFinTime /= time.Duration(n)
	avgStat.NwLoginAFFinTime /= time.Duration(n)
	avgStat.CpLoginComTime /= time.Duration(n)
	avgStat.CpLoginSignTime /= time.Duration(n)
	avgStat.CpLoginFinTime /= time.Duration(n)
	avgStat.RegComputationTime /= time.Duration(n)
	avgStat.RegNetworkTime /= time.Duration(n)
	avgStat.RegTotalTime /= time.Duration(n)
	avgStat.LoginComputationTime /= time.Duration(n)
	avgStat.LoginNetworkTime /= time.Duration(n)
	avgStat.LoginTotalTime /= time.Duration(n)

	// fomat the result as readable string
	res := fmt.Sprintf("[Benchmark AKMA Protocol (run %d times)]\n", n)
	res += fmt.Sprintf("[[=== Register ===]]\n")
	res += fmt.Sprintf("(net)Request AF Challenge Time: %v\n", avgStat.NwRegAFReqTime)
	res += fmt.Sprintf("(net)Request HN 2POS Keygen Time: %v\n", avgStat.NwRegHNReqTime)
	res += fmt.Sprintf("(net)2POS Commit to HN Time: %v\n", avgStat.NwRegHNComTime)
	res += fmt.Sprintf("(net)2POS Finish to HN Time: %v\n", avgStat.NwRegHNFinTime)
	res += fmt.Sprintf("(net)Finish to AF Time: %v\n", avgStat.NwRegAFFinTime)
	res += fmt.Sprintf("(comp)Client 2POS Commit Time: %v\n", avgStat.CpRegComTime)
	res += fmt.Sprintf("(comp)Client 2POS Sign Time: %v\n", avgStat.CpRegSignTime)
	res += fmt.Sprintf("(comp)Client 2POS Finish Time: %v\n", avgStat.CpRegFinTime)
	res += fmt.Sprintf("[[=== Login ===]]\n")
	res += fmt.Sprintf("(net)Request AF Challenge Time: %v\n", avgStat.NwLoginAfReqTime)
	res += fmt.Sprintf("(net)Request HN 2POS Time: %v\n", avgStat.NwLoginHNReqTime)
	res += fmt.Sprintf("(net)Finish 2POS with HN Time: %v\n", avgStat.NwLoginHNFinTime)
	res += fmt.Sprintf("(net)Finish with AF Time: %v\n", avgStat.NwLoginAFFinTime)
	res += fmt.Sprintf("(comp)Client 2POS Commit Time: %v\n", avgStat.CpLoginComTime)
	res += fmt.Sprintf("(comp)Client 2POS Sign Time: %v\n", avgStat.CpLoginSignTime)
	res += fmt.Sprintf("(comp)Client 2POS Finish Time: %v\n", avgStat.CpLoginFinTime)
	res += fmt.Sprintf("[[=== Total ===]]\n")
	res += fmt.Sprintf("Register Computation Time: %v\n", avgStat.RegComputationTime)
	res += fmt.Sprintf("Register Network Time: %v\n", avgStat.RegNetworkTime)
	res += fmt.Sprintf("Register Total Time: %v\n", avgStat.RegTotalTime)
	res += fmt.Sprintf("Login Computation Time: %v\n", avgStat.LoginComputationTime)
	res += fmt.Sprintf("Login Network Time: %v\n", avgStat.LoginNetworkTime)
	res += fmt.Sprintf("Login Total Time: %v\n", avgStat.LoginTotalTime)
	res += fmt.Sprintf("---------------\n")
	res += fmt.Sprintf("[Finish At: %v]\n", time.Now().Format("2006-01-02 15:04:05"))
	return fmt.Sprintf(res)
}

func RunBenchmarkNormalProtocol(n int, hnUrl, afUrl string) string {
	stat := make([]*NormalAkmaProtocolBenchmarkStat, n)
	for i := 0; i < n; i++ {
		stat[i] = benchmark5gAKMA(hnUrl, afUrl)
	}
	// compute the average time of each items
	var avgStat NormalAkmaProtocolBenchmarkStat
	for i := 0; i < n; i++ {
		avgStat.NwHNReqTime += stat[i].NwHNReqTime
		avgStat.NwAFReqTime += stat[i].NwAFReqTime
		avgStat.NwAFFinTime += stat[i].NwAFFinTime
		avgStat.CpHnReqTime += stat[i].CpHnReqTime
		avgStat.CpAFReqTime += stat[i].CpAFReqTime
		avgStat.CpAFFinTime += stat[i].CpAFFinTime
		avgStat.ComputationTime += stat[i].ComputationTime
		avgStat.NetworkTime += stat[i].NetworkTime
		avgStat.TotalTime += stat[i].TotalTime
	}
	avgStat.NwHNReqTime /= time.Duration(n)
	avgStat.NwAFReqTime /= time.Duration(n)
	avgStat.NwAFFinTime /= time.Duration(n)
	avgStat.CpHnReqTime /= time.Duration(n)
	avgStat.CpAFReqTime /= time.Duration(n)
	avgStat.CpAFFinTime /= time.Duration(n)
	avgStat.ComputationTime /= time.Duration(n)
	avgStat.NetworkTime /= time.Duration(n)
	avgStat.TotalTime /= time.Duration(n)

	// fomat the result as readable string
	res := fmt.Sprintf("[Benchmark 5G AKMA Protocol (run %d times)]\n", n)
	res += fmt.Sprintf("[[=== Register ===]]\n")
	res += fmt.Sprintf("(net)Request HN Time: %v\n", avgStat.NwHNReqTime)
	res += fmt.Sprintf("(net)Request AF Time: %v\n", avgStat.NwAFReqTime)
	res += fmt.Sprintf("(net)Finish AF Time: %v\n", avgStat.NwAFFinTime)
	res += fmt.Sprintf("(comp)Client HN Request Time: %v\n", avgStat.CpHnReqTime)
	res += fmt.Sprintf("(comp)Client AF Request Time: %v\n", avgStat.CpAFReqTime)
	res += fmt.Sprintf("(comp)Client AF Finish Time: %v\n", avgStat.CpAFFinTime)
	res += fmt.Sprintf("[[=== Total ===]]\n")
	res += fmt.Sprintf("Computation Time: %v\n", avgStat.ComputationTime)
	res += fmt.Sprintf("Network Time: %v\n", avgStat.NetworkTime)
	res += fmt.Sprintf("Total Time: %v\n", avgStat.TotalTime)
	res += fmt.Sprintf("---------------\n")
	res += fmt.Sprintf("[Finish At: %v]\n", time.Now().Format("2006-01-02 15:04:05"))
	return fmt.Sprintf(res)
}
