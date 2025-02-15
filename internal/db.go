package internal

import (
	"database/sql"
	"strconv"
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
	body text NOT NULL DEFAULT '',
	author_id BIGINT NOT NULL,
	retweeted_tweet_id BIGINT,

	tweeted TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

	UNIQUE(retweeted_tweet_id, author_id),

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

CREATE TABLE IF NOT EXISTS tweet_like (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	tweet_id BIGINT NOT NULL,
	person_id BIGINT NOT NULL,
	UNIQUE(tweet_id, person_id)
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
	RetweetedTweet   *Tweet        `db:"-" json:"RetweetedTweet"`
	Author           Person        `db:"-"`
	Liked            bool          `db:"liked"`
	Likes            int           `db:"likes"`
	Retweeted        bool          `db:"retweeted"`
	Retweets         int           `db:"retweets"`
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

func (db *TwitterCloneDB) GetTweetsByPersonId(personId int64) ([]Tweet, error) {
	var tweets []Tweet
	query := `
	select tweet.*, likes, retweets, person.username as AuthorUsername, person.HasProfilePic
	from (
		select tweet.id as tweet_id, count(tweet_like.*) as likes, count(retweets.*) as retweets
		from tweet
		left join tweet_like on tweet_like.tweet_id = tweet.id
		left join tweet as retweets on tweet.id = retweets.retweeted_tweet_id
		where tweet.author_id = $1
		group by tweet.id
	) a
	inner join tweet on tweet.id = a.tweet_id
	inner join person on person.id = tweet.author_id
	order by tweeted desc;
	`

	err := db.dbConn.Select(&tweets, query, personId)
	if err != nil {
		return nil, err
	}

	return tweets, nil

}

func (db *TwitterCloneDB) GetPerson(personId int64, options PersonQueryOptionsBuilder) (*Person, error) {
	var person Person
	var tweets []Tweet

	err := db.dbConn.Get(&person, "SELECT id, username, email, description, hasprofilepic FROM person WHERE id = $1", personId)

	if err != nil {
		return nil, err
	}

	if options.IncludeTweets {
		query := `
			select tweet.*, likes, person.username as AuthorUsername, person.HasProfilePic
			from (
				select tweet.id as tweet_id, count(tweet_like.*) as likes
				from tweet
				left join tweet_like on tweet_like.tweet_id = tweet.id
				where tweet.author_id = $1
				group by tweet.id
			) a
			inner join tweet on tweet.id = a.tweet_id
			inner join person on person.id = tweet.author_id
		`
		err = db.dbConn.Select(&tweets, query, strconv.FormatInt(person.Id, 10))
		if err != nil {
			return nil, err
		}

		person.Tweets = tweets

	}
	return &person, nil
}
