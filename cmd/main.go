package main

import (
	"fmt"
	"os"

	"github.com/python357-1/twitter-clone/internal"
)

func main() {
	options := internal.TwitterCloneServerOptions{
		Port:             "8080",
		Secret:           os.Getenv("TWTCLONE_JWT_SECRET"),
		ConnectionString: os.Getenv("TWTCLONE_DBCONNSTRING"),
		CertPath:         os.Getenv("TWTCLONE_SSL_CERT"),
		KeyPath:          os.Getenv("TWTCLONE_SSL_KEY"),
	}

	if true { // for debugging
		fmt.Println("PORT: ", options.Port)
		fmt.Println("TWTCLONE_JWT_SECRET: ", options.Secret)
		fmt.Println("TWTCLONE_DBCONNSTRING: ", options.ConnectionString)
		fmt.Println("TWTCLONE_SSL_CERT: ", options.CertPath)
		fmt.Println("TWTCLONE_SSL_KEY: ", options.KeyPath)
	}

	server, err := internal.CreateServer(options)
	if err != nil {
		panic(err)
	}
	server.Run()

}
