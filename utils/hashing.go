package utils

import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// just panic here. the only recoverable error that this could have would really be
		// if we gave the HashPassword function bad data, but that shouldnt happen. other
		// errors mean the server is basically out of resources, so just give up
		panic(err)
	}
	return string(hash)
}
