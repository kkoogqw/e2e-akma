package hn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"ppakma/osign"
	"sync"
)

// http handler
func pingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

// register
func registerRequestHandler(c *gin.Context) {
	supi := c.Query("supi")
	if supi == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "supi is required",
		})
		return
	}
	_, pk, err := ueRegistrationRequest(supi)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "account registration failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"public_key": &pk,
		"message":    "ok",
	})
	return
}

func registerCommitHandler(c *gin.Context) {
	var req ClientRegisterCommitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
		})
		return
	}
	sigma, tag, _ := ueRegistrationCommit(req.Supi, req.CommitUID)
	osPk, osPf, err := ueRegistrationSign(req.Supi, req.CommitOsKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "signing the commit failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"uid_signature": &sigma,
		"uid_tag":       &tag,
		"osign_pk":      &osPk,
		"osign_pf":      &osPf,
		"message":       "ok",
	})
	return
}

func registerFinishHandler(c *gin.Context) {
	var req ClientRegisterFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
		})
		return
	}
	clientPreSign := &osign.ClientPreSign{
		EncKey: req.PreOsign.EncKey,
		M:      &req.PreOsign.M,
		R:      osign.ParseEcPoint(&req.PreOsign.R),
		Pi: &osign.DlogProof{
			R: osign.ParseEcPoint(&req.PreOsign.Pi.R),
			S: &req.PreOsign.Pi.S,
			C: &req.PreOsign.Pi.C,
		},
		PailliarPubKey: &req.PreOsign.PailliarPubKey,
	}
	sigma, err := ueRegistrationFinish(req.Supi, clientPreSign)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "signing the commit failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"cipher":  hex.EncodeToString(sigma.Ct),
		"message": "ok",
	})
	return
}

// login
func loginRequestHandler(c *gin.Context) {
	var req ClientLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
		})
		return
	}
	osPk, osPf, err := ueLoginRequest(req.Supi, req.Commit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "signing the commit failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"osign_tpk": &osPk,
		"osign_tpf": &osPf,
		"message":   "ok",
	})
	return
}

func loginFinishHandler(c *gin.Context) {
	var req ClientLoginFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
		})
		return
	}
	clientPreSign := &osign.ClientPreSign{
		EncKey: req.PreOsign.EncKey,
		M:      &req.PreOsign.M,
		R:      osign.ParseEcPoint(&req.PreOsign.R),
		Pi: &osign.DlogProof{
			R: osign.ParseEcPoint(&req.PreOsign.Pi.R),
			S: &req.PreOsign.Pi.S,
			C: &req.PreOsign.Pi.C,
		},
		PailliarPubKey: &req.PreOsign.PailliarPubKey,
	}
	sigma, err := ueLoginFinish(req.Supi, clientPreSign)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "signing the commit failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"cipher":  hex.EncodeToString(sigma.Ct),
		"message": "ok",
	})
	return
}

// normal akma handler
var hnMasterKey = "9e83e05bbf9b5db17ac0deec3b7ce6cba983f6dc50531c7a919f28d5fb3696c3"

type AkmaSession struct {
	Supi   string
	Afid   string
	K_akma string
	K_af   string
	Atid   string
}

// var akmaSessions = make(map[string]AkmaSession)
var akmaSessions sync.Map

type UeAkmaRequest struct {
	Supi  string `json:"supi"`
	Nonce string `json:"nonce"`
	Afid  string `json:"afid"`
}

func akmaUeRequestHandler(c *gin.Context) {
	var req UeAkmaRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
		})
		return
	}
	keyBytes := []byte(hnMasterKey)
	// k_asuf = hmac(msk, supi||nonce||afid)
	nc := make([]byte, 0)
	nc = append(nc, []byte(req.Supi)...)
	nc = append(nc, []byte(req.Nonce)...)
	nc = append(nc, []byte(req.Afid)...)

	h0 := hmac.New(sha256.New, keyBytes)
	h0.Write(nc)
	k_ausf := hex.EncodeToString(h0.Sum(nil))

	message1 := make([]byte, 0)
	message1 = append(message1, 0x80)
	message1 = append(message1, []byte("AKMA")...)
	message1 = append(message1, 0x00, 0x04)
	message1 = append(message1, []byte(req.Supi)...)
	message1 = append(message1, 0x0f)

	h1 := hmac.New(sha256.New, []byte(k_ausf))
	h1.Write(message1)
	k_akma := h1.Sum(nil)

	message2 := make([]byte, 0)
	message2 = append(message2, 0x81)
	message2 = append(message2, []byte("A-TID")...)
	message2 = append(message2, 0x00, 0x05)
	message2 = append(message2, []byte(req.Supi)...)
	message2 = append(message2, 0x0f)

	h2 := hmac.New(sha256.New, []byte(k_ausf))
	h2.Write(message2)
	atid := h2.Sum(nil)

	message3 := make([]byte, 0)
	message3 = append(message3, 0x82)
	message3 = append(message3, []byte(req.Afid)...)
	message3 = append(message3, []byte(string(len(req.Afid)))...)

	h3 := hmac.New(sha256.New, k_akma)
	h3.Write(message3)
	k_af := h3.Sum(nil)

	// store session
	session := AkmaSession{
		Supi:   req.Supi,
		Afid:   req.Afid,
		K_akma: hex.EncodeToString(k_akma),
		K_af:   hex.EncodeToString(k_af),
		Atid:   hex.EncodeToString(atid),
	}
	akmaSessions.Store(req.Supi, session)
	c.JSON(http.StatusOK, gin.H{
		"key":     k_ausf,
		"message": "ok",
	})
	return
}

type AfAkmaRequest struct {
	Afid string `json:"afid"`
	Supi string `json:"supi"`
	Atid string `json:"atid"`
}

func akmaAfRequestHandler(c *gin.Context) {
	var req AfAkmaRequest
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
	if session.Afid != req.Afid {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "afid not match",
		})
		return
	}
	akmaSessions.Delete(req.Supi)
	c.JSON(http.StatusOK, gin.H{
		"key":     session.K_af,
		"atid":    session.Atid,
		"message": "ok",
	})
	return
}
