TWTCLONE_JWT_SECRET="the boys going to the ice cream shop love mustard flavored ice cream" \
TWTCLONE_DBCONNSTRING="postgres://postgres:DEVELOPMENT@localhost:5432/postgres?sslmode=disable" \
TWTCLONE_SSL_CERT="/home/jordan/twtrclone.jordanbc.xyz/fullchain.pem" \
TWTCLONE_SSL_KEY="/home/jordan/twtrclone.jordanbc.xyz/privkey.pem" \
go run ./cmd/main.go