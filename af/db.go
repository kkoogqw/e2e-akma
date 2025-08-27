package af

import (
	"errors"
	"gorm.io/gorm"
	"time"
)

var afDB *gorm.DB

type UserAccount struct {
	Id              uint      `json:"id" gorm:"primary_key"`
	Uid             string    `json:"uid" gorm:"unique"`
	Username        string    `json:"username"`
	VerificationKey string    `json:"verification_key"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func createUserAccount(uid, username, verificationKey string) (*UserAccount, error) {
	var count int64
	// check if uid is already exist
	afDB.Model(&UserAccount{}).Where("uid = ?", uid).Count(&count)
	if count > 0 {
		return nil, errors.New("uid already exist")
	}

	ua := UserAccount{
		Uid:             uid,
		Username:        username,
		VerificationKey: verificationKey,
	}
	result := afDB.Create(&ua)
	if result.Error != nil {
		return nil, result.Error
	}
	return &ua, nil
}

func getUserAccount(uid string) (*UserAccount, error) {
	var ua UserAccount
	result := afDB.Where("uid = ?", uid).First(&ua)
	if result.Error != nil {
		return nil, result.Error
	}
	return &ua, nil
}
