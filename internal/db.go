package internal

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
)

var schema = `CREATE TABLE IF NOT EXISTS person (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	username text UNIQUE,
	password text,
	email text UNIQUE
);

CREATE TABLE IF NOT EXISTS tweet (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	body text,
	author_id BIGINT NOT NULL,
	retweeted_tweet_id BIGINT,

	CONSTRAINT fk_tweet_author FOREIGN KEY (author_id) references person(id),
	CONSTRAINT fk_retweeted_tweet FOREIGN KEY (retweeted_tweet_id) references tweet(id),
	CONSTRAINT must_have_content_or_retweet CHECK (
		NOT (body IS NULL AND retweeted_tweet_id IS NULL)

		-- the only invalid case is if body and retweeted_tweet_id is null;
		-- body not null and retweeted_tweet_id null: original tweet
		-- body null and retweeted_tweet_id not null: retweet with no body
		-- body not null and retweeted_tweet_id not null: retweet with body
	)
);
`

type Like struct {
	PersonId int64 `db:"personid"`
	TweetId  int64 `db:"tweetid"`
}

type TweetComments struct {
	PersonId int64  `db:"personid"`
	TweetId  int64  `db:"tweetid"`
	Message  string `db:"message"`
}

type Person struct {
	Id           int64  `db:"id"`
	Username     string `db:"username"`
	Email        string `db:"email"`
	PasswordHash string `db:"password" json:"-"` // Password, hashed as SHA256
	Tweets       []Tweet
	Retweets     []Tweet
	LikedTweets  []Tweet
}

type Tweet struct {
	Id               int64         `db:"id"`
	Body             string        `db:"body"`
	AuthorId         int64         `db:"author_id"`
	RetweetedTweetId sql.NullInt64 `db:"retweeted_tweet_id"`
	Author           Person        `db:"-"`
}

type PersonQueryOptionsBuilder struct {
	IncludeTweets bool
}

func (options *PersonQueryOptionsBuilder) AddTweets() *PersonQueryOptionsBuilder {
	options.IncludeTweets = true
	return options
}

type TwitterCloneDB struct {
	dbConn *sqlx.DB
}

func CreateDBInstance(db *sqlx.DB) TwitterCloneDB {
	return TwitterCloneDB{
		dbConn: db,
	}
}

func (db *TwitterCloneDB) GetPerson(personId int64, options PersonQueryOptionsBuilder) (*Person, error) {
	var person Person
	var tweets []Tweet

	err := db.dbConn.Get(&person, "SELECT id, username, email FROM person WHERE id = $1", personId)

	if err != nil {
		return nil, err
	}

	err = db.dbConn.Select(&tweets, "SELECT * FROM tweet WHERE author_id = $1 AND retweeted_tweet_id IS NULL", personId)
	if err != nil {
		return nil, err
	}

	person.Tweets = tweets
	return &person, nil
}
