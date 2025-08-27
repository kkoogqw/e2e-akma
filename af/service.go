package af

import (
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
)

func RunAppFunctionService() {
	db, err := gorm.Open(sqlite.Open("../af/state/af.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
		return
	}

	afDB = db
	if !afDB.Migrator().HasTable(&UserAccount{}) {
		err := afDB.Migrator().CreateTable(&UserAccount{})
		if err != nil {
			log.Fatal("Failed to create table UEAccount:", err)
			return
		}
	}
	certFile := "../af/state/certs/AF-DEMO.pem"
	keyFile := "../af/state/certs/AF-DEMO.priv.key"

	// set release mode
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.HEAD("/ping", pingHandler)
	afRouter := r.Group("/api/af")
	{
		regRouter := afRouter.Group("/reg")
		{
			regRouter.GET("/request", registerRequestHandler)
			regRouter.POST("/finish", registerFinishHandler)
		}

		loginRouter := afRouter.Group("/login")
		{
			loginRouter.GET("/request", loginRequestHandler)
			loginRouter.POST("/finish", loginFinishHandler)
		}
	}
	af5gAkmaRouter := r.Group("/api/af/akma")
	{
		af5gAkmaRouter.POST("/uerequest", akmaUeRequestHandler)
		af5gAkmaRouter.POST("/uefinish", akmaUeFinishHandler)
	}

	err = r.RunTLS(":18081", certFile, keyFile)
	if err != nil {
		log.Fatal("Failed to start App-Function service:", err)
		return
	}
}
