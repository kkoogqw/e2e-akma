package hn

import (
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"log"
)

type clientLoginRequest struct {
	Stage int    `json:"stage"`
	Supi  string `json:"supi"`
	Data  string `json:"data"`
}

func RunHomeNetworkService() {
	db, err := gorm.Open(sqlite.Open("../hn/state/hn.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
		return
	}
	hnDB = db
	// generate the secret key
	generateHNSignKey()
	// create the table
	if !hnDB.Migrator().HasTable(&UEAccount{}) {
		err := hnDB.Migrator().CreateTable(&UEAccount{})
		if err != nil {
			log.Fatal("Failed to create table UEAccount:", err)
			return
		}
	}

	certFile := "../hn/state/certs/HN-DEMO.pem"
	keyFile := "../hn/state/certs/HN-DEMO.priv.key"

	// set release mode
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.HEAD("/ping", pingHandler)
	hnRouter := r.Group("/api/hn")
	{
		regRouter := hnRouter.Group("/reg")
		{
			regRouter.GET("/request", registerRequestHandler)
			regRouter.POST("/commit", registerCommitHandler)
			regRouter.POST("/finish", registerFinishHandler)
		}

		loginRouter := hnRouter.Group("/login")
		{
			loginRouter.POST("/request", loginRequestHandler)
			loginRouter.POST("/finish", loginFinishHandler)
		}
	}

	hn5gAkmaRouter := r.Group("/api/hn/akma")
	{
		hn5gAkmaRouter.POST("/uerequest", akmaUeRequestHandler)
		hn5gAkmaRouter.POST("/afrequest", akmaAfRequestHandler)
	}

	err = r.RunTLS(":18080", certFile, keyFile)
	if err != nil {
		log.Fatal("Failed to start Home Network service:", err)
		return
	}
}
