package internal

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
)

var schema = `CREATE TABLE IF NOT EXISTS person (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	username text UNIQUE,
	password text,
	email text UNIQUE,
	description text DEFAULT ''::text NOT NULL,
	HasProfilePic bool NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS follow (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	follower BIGINT references person(id),
	followed BIGINT references person(id),

	CONSTRAINT cannot_follow_self CHECK (NOT (follower = followed))
);

CREATE TABLE IF NOT EXISTS tweet (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	body text,
	author_id BIGINT NOT NULL,
	retweeted_tweet_id BIGINT,

	tweeted TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

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

DO $$ BEGIN
	CREATE TYPE notification_type AS ENUM (
		'like', 
		'retweet', 
		'reply', 
		'follow', 
		'message', 
		'mention', 
		'quote_tweet'
	);
EXCEPTION
	WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS notification (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	for_user BIGINT NOT NULL references person(id),
	triggered_by BIGINT references person(id),
	type notification_type NOT NULL,
	extra_data JSONB,

	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	is_read BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS message (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	sent_to BIGINT NOT NULL references person(id),
	sent_from BIGINT NOT NULL references person(id),
	body text NOT NULL,
	
	sent TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	is_read BOOLEAN DEFAULT FALSE
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
	Id            int64  `db:"id"`
	Username      string `db:"username"`
	Email         string `db:"email"`
	PasswordHash  string `db:"password" json:"-"` // Password, hashed as SHA256
	Description   string `db:"description"`
	HasProfilePic bool   `db:"hasprofilepic"`
	Tweets        []Tweet
	Retweets      []Tweet
	LikedTweets   []Tweet
}

type Follow struct {
	Id         int64 `db:"id"`
	FollowerId int64 `db:"follower"`
	FollowedId int64 `db:"followed"`
}

type Tweet struct {
	Id               int64         `db:"id"`
	Body             string        `db:"body"`
	AuthorId         int64         `db:"author_id"`
	RetweetedTweetId sql.NullInt64 `db:"retweeted_tweet_id"`
	Author           Person        `db:"-"`
	Tweeted          time.Time
	HasProfilePic    bool // URL
	AuthorUsername   string
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

	err := db.dbConn.Get(&person, "SELECT id, username, email, description, hasprofilepic FROM person WHERE id = $1", personId)

	if err != nil {
		return nil, err
	}

	err = db.dbConn.Select(&tweets, "SELECT tweet.*, person.username as AuthorUsername, person.HasProfilePic as HasProfilePic FROM tweet INNER JOIN person on person.id = tweet.author_id WHERE author_id = $1 AND retweeted_tweet_id IS NULL", personId)
	if err != nil {
		return nil, err
	}

	person.Tweets = tweets
	return &person, nil
}
