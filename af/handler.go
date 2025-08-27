package af

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/point"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"ppakma/hn"
	"ppakma/osign"
	"sync"
	"time"
)

func pingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

type sessionInfo struct {
	Uid             string
	Username        string
	Challenge       string
	VerificationKey string
	HnServerVfKey   *point.Point
}

var AfServerId = "AppFunction@b53ca8af879f65"

// var registerSessions = make(map[string]sessionInfo)
// var loginSessions = make(map[string]sessionInfo)
var registerSessions2 sync.Map
var loginSessions2 sync.Map

var hnSignPkX = "87652964065115809494188517548658104829161315810155224409981043493657545974358"
var hnSignPkY = "2024758924903999716801351854344759900649667659239532207673564297212915606506"

var CorePubKeyPrimeHex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"

var CorePubKeyGenHex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

func generateChallenge() string {
	r1 := bigint.GetRandom().String()
	r2 := bigint.GetRandom().String()
	r := fmt.Sprintf("%s%s", r1, r2)
	hash := sha256.New()
	hash.Write([]byte(r))
	return hex.EncodeToString(hash.Sum(nil))
}

/**
 * Register
 */

func registerRequestHandler(c *gin.Context) {
	uid := c.Query("uid")
	username := c.Query("username")
	if uid == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "uid/username is required",
		})
		return
	}
	// generate a challenge
	ch := generateChallenge()
	c.JSON(http.StatusOK, gin.H{
		"challenge": ch,
		"message":   "ok",
	})
	// set state
	pkx := new(big.Int)
	pky := new(big.Int)
	pkx.SetString(hnSignPkX, 10)
	pky.SetString(hnSignPkY, 10)

	hnSignVfKey := osign.ParseEcPoint(&osign.ApiEcPoint{
		X: *pkx,
		Y: *pky,
	})
	newSession := sessionInfo{
		Uid:           uid,
		Username:      username,
		Challenge:     ch,
		HnServerVfKey: hnSignVfKey,
	}
	registerSessions2.Store(uid, newSession)
	return
}

type UserRegisterFinishRequest struct {
	Uid         string                `json:"uid"`
	UidTag      *hn.ClientRegisterTag `json:"uid_tag"`
	SignatureHn *ecdsa.Signature      `json:"signature_hn"`
	SignatureOs *ecdsa.Signature      `json:"signature_os"`
	UserVfKey   *osign.ApiEcPoint     `json:"user_vf_key"`
	Rnd1        string                `json:"rnd1"`
	Rnd2        string                `json:"rnd2"`
}

func registerFinishHandler(c *gin.Context) {
	var req UserRegisterFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
		})
		// delete session
		registerSessions2.Delete(req.Uid)
		return
	}
	// check session
	value, ok := registerSessions2.Load(req.Uid)
	session := value.(sessionInfo)

	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "session not found",
		})
		return
	}
	jsonEncodedClientOsPubKey, err := json.Marshal(req.UserVfKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "encode client osign pubkey failed",
		})
		registerSessions2.Delete(req.Uid)
		return
	}
	rnd1, err := hex.DecodeString(req.Rnd1)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "decode rnd1 failed",
		})
		registerSessions2.Delete(req.Uid)
		return
	}
	// check signatures:
	commit1 := sha256.New()
	commit1.Write([]byte(session.Uid))
	commit1.Write([]byte(AfServerId))
	commit1.Write([]byte(session.Challenge))
	commit1.Write(jsonEncodedClientOsPubKey)
	commit1.Write(rnd1)
	com1 := commit1.Sum(nil)

	// verify hn signature
	vf := ecdsa.Verify(
		session.HnServerVfKey,
		bigint.HashStringToBigInt(hex.EncodeToString(com1)),
		req.SignatureHn,
		secp256k1.GetSecp256k1())
	if !vf {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid hn signature",
		})
		registerSessions2.Delete(req.Uid)
		return
	}

	rnd2, err := hex.DecodeString(req.Rnd2)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "decode rnd2 failed",
		})
		registerSessions2.Delete(req.Uid)
		return
	}

	commit2 := sha256.New()
	commit2.Write([]byte(AfServerId))
	commit2.Write([]byte(session.Challenge))
	commit2.Write(rnd2)
	com2 := commit2.Sum(nil)

	fmt.Println("[AF]com2: ", hex.EncodeToString(com2))
	userVk := osign.ParseEcPoint(req.UserVfKey)
	vf = ecdsa.Verify(
		userVk,
		bigint.HashBytesToBigInt(com2),
		req.SignatureOs,
		secp256k1.GetSecp256k1())
	if !vf {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid os signature",
		})
		registerSessions2.Delete(req.Uid)
		return
	}

	// rerandomize the user tag:
	p := fromHex(CorePubKeyPrimeHex)
	//g := fromHex(CorePubKeyGenHex)
	r, err := rand.Int(rand.Reader, p)
	randomizedTag := &hn.ClientRegisterTag{
		C1: new(big.Int).Exp(req.UidTag.C1, r, p),
		C2: new(big.Int).Exp(req.UidTag.C2, r, p),
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "generate random r failed",
		})
		registerSessions2.Delete(req.Uid)
		return
	}

	// store the user:
	user, err := createUserAccount(session.Uid, session.Username, string(jsonEncodedClientOsPubKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to create user account",
		})
		registerSessions2.Delete(req.Uid)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
		"user":    user,
		"tag":     randomizedTag,
	})
	return
}

func fromHex(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("failed to parse hex number")
	}
	return n
}

/**
 * Login
 */

func loginRequestHandler(c *gin.Context) {
	uid := c.Query("uid")
	if uid == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "uid/username is required",
		})
		return
	}
	user, err := getUserAccount(uid)
	if err != nil || user == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "get user account failed",
		})
		return
	}
	ch := generateChallenge()

	c.JSON(http.StatusOK, gin.H{
		"challenge": ch,
		"message":   "ok",
	})

	newSession := sessionInfo{
		Uid:             uid,
		Username:        user.Username,
		Challenge:       ch,
		VerificationKey: user.VerificationKey,
	}
	loginSessions2.Store(uid, newSession)
	return
}

type UserLoginFinishRequest struct {
	Uid         string           `json:"uid"`
	SignatureOs *ecdsa.Signature `json:"signature_os"`
	Rnd         string           `json:"rnd"`
}

func loginFinishHandler(c *gin.Context) {
	var req UserLoginFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
		})
		// delete session
		loginSessions2.Delete(req.Uid)
		return
	}
	// check session
	value, ok := loginSessions2.Load(req.Uid)
	session := value.(sessionInfo)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "session not found",
		})
		return
	}

	rnd, err := hex.DecodeString(req.Rnd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "decode rnd2 failed",
		})
		loginSessions2.Delete(req.Uid)
		return
	}

	commit := sha256.New()
	commit.Write([]byte(AfServerId))
	commit.Write([]byte(session.Challenge))
	commit.Write(rnd)
	com := commit.Sum(nil)

	// parse the user verification key
	var userVk osign.ApiEcPoint
	err = json.Unmarshal([]byte(session.VerificationKey), &userVk)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "decode user verification key failed",
		})
		loginSessions2.Delete(req.Uid)

		return
	}
	vf := ecdsa.Verify(
		osign.ParseEcPoint(&userVk),
		bigint.HashBytesToBigInt(com),
		req.SignatureOs,
		secp256k1.GetSecp256k1())
	if !vf {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid os signature: failed to login.",
		})
		loginSessions2.Delete(req.Uid)

		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
	})
	return
}

// normal akma handler
type AkmaSession struct {
	Supi string
	Afid string
	Atid string
	K_af string
}

var akmaSessions sync.Map
var hnURL = "https://127.0.0.1:18080"

type UeAkmaRequest struct {
	Supi string `json:"supi"`
	Atid string `json:"atid"`
}
type UeAkmaFinish struct {
	Supi string `json:"supi"`
	Tag  string `json:"tag"`
}

func akmaUeRequestHandler(c *gin.Context) {
	var req UeAkmaRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
		})
		return
	}
	// create session
	akmaSession := AkmaSession{
		Supi: req.Supi,
		Afid: AfServerId,
		Atid: req.Atid,
	}
	akmaSessions.Store(req.Supi, akmaSession)

	// request to hn
	akmaReq := &hn.AfAkmaRequest{
		Supi: req.Supi,
		Afid: AfServerId,
		Atid: req.Atid,
	}
	body, err := json.Marshal(akmaReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to marshal request",
		})
		return
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := &http.Client{
		Timeout:   time.Minute,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	resp, err := sendPostRequest(hnURL, "/api/hn/akma/afrequest", body, client)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to send request to hn",
		})
		return
	}
	var respData map[string]interface{}
	err = json.Unmarshal(resp, &respData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to unmarshal response",
		})
		return
	}
	// update session with k_af
	akmaSession.K_af = respData["key"].(string)
	akmaSessions.Store(req.Supi, akmaSession)

	c.JSON(http.StatusOK, gin.H{
		"key":     respData["key"],
		"message": "ok",
	})
	return
}

func akmaUeFinishHandler(c *gin.Context) {
	var req UeAkmaFinish
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
		})
		return
	}
	value, ok := akmaSessions.Load(req.Supi)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "session not found",
		})
		return
	}
	session := value.(AkmaSession)
	// verify tag with HMAC
	h := hmac.New(sha256.New, []byte(session.K_af))
	h.Write([]byte(session.Afid))
	h.Write([]byte(session.Supi))
	h.Write([]byte(session.Atid))
	tag := h.Sum(nil)
	if req.Tag != hex.EncodeToString(tag) {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "tag not match",
		})
		return
	}
	akmaSessions.Delete(req.Supi)
	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
	})
	return

}

func sendPostRequest(baseUrl, api string, body []byte, client *http.Client) ([]byte, error) {
	u, err := url.Parse(baseUrl + api)
	if err != nil {
		panic(err)
	}

	resp, err := client.Post(u.String(), "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Fatal("Failed to send request:", u.String(), err)
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal("Failed to close response body:", err)
		}
	}(resp.Body)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response body:", err)
		return nil, err
	}

	return respBody, nil
}
