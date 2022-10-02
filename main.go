package main

import (
	"context"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
)

// TODO: Remember users selected tags (use a cookie?).
// TODO: Sort by new
// TODO: README
// TODO: Tests
//
// TMV1.0 GOALS:
// // Users
// // Tags
// // Starting threads with tags
// // Replying to threads and other replies
// // Sorting: new, hot, dead
// // threads last a week?
// // // > Algorithm?
//
//
// TMV2.0 GOALS:
// // Tag cloud
// // Allow users to add tags to threads already posted
// // Configurable sorting
// // Themes
// // Awards

// TagMachine takes inspiration from reddit, twitter, hacker news, and 4chan
// TagMachine is meant to be used as a real-time news source

// How TagMachine should work:
// There are two sets of tags, the default tags (provided by TagMachine) and
//   auxiliary tags created by users
//
// Each user thread is required to have a default tag, and an auxiliary tag.
//
// TagMachine adds the aux tags to a sorted set in redis.
//
// TagMachine will only display and allow sorting using the 20 highest scoring
//   aux tags (and default tags)
// The tags score is incremented when a user posts or replies to a thread with
//   that tag, and decremented after a certain amount of time with no
//   threads/replies.
// Threads behave similar to tags, but are displayed in a different location
//   (under the tags)
// A thread is stored in a sorted set with a score and that score is
//   incremented when a user replies to that thread. The score is decremented
//   using a time-to-score ratio that eventually becomes zero, and the thread
//   is removed. (this may change)
// Most threads should not last more than 72 hours. Threads with no activity
//   should be removed before threads with lots of activity.
// Threads can be sorted by rank and post date.
// Users have scores and have privileges based on those scores
//   Ex.
//   - users with under 10 points can only post 1 thread an hour and 5 replies
//   - etc
//   - Not implemented yet
// Each auxiliary tag can only have 100 threads, when the 101st thread is
//   posted, the "weakest" thread is determined by an algorithm, and then
//   removed, making space for the new thread
// Each thread can only have 350 replies, then it will be auto-reposted with
//   a special badge indicating its popularity. This can continue for ???
//
// Goal: To quickly relay and funnel real-time world events into an easily
//       digested stream of information
//
// Goal: To eventually archive popular discussions/tags and create an event
//       time-line and word-cloud
//
// Rules:
//   - No spam/advertising
//   - No bots or organized information suppression
//   - No sexualization of minors
//   - No racism/sexism
//   - No links to illegal content
//   - No posting personal information of anyone without consent
//   - No harassment of other users
//
//
// Hacker news: Opinions repressed/suppressed
//              Too snarky/high brow
//
// Reddit: Past its prime
//         Buggy
//         Plagued by shills/corporate/agendas with no attempt at over sight
//         (perhaps the moderators support it)
//
// 4chan: Too many shills/cringe/incels
//
//
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//

// credentials are user credentials and are used in the HTML templates and also
// by handlers that do authorized requests
type credentials struct {
	Name       string   `json:"username"`
	Password   string   `json:"password"`
	IsLoggedIn bool     `json:"isLoggedIn"`
	Posts      []string `json:"posts"`
	Score      uint     `json:"score"`
	jwt.StandardClaims
	// Add google login one day...
	//
	// IP         string `json:"IP"`
	// HasGoogle  bool   `json:"hasGoogle"`
	// GoogleCredentials googleCredentials `json:"gcred"`
	// GoogleToken string `json:"googleToken"`
}

// pageData is used in the HTML templates as the main page model. It is
// composed of credentials, postData, and threadData.
type pageData struct {
	UserData    *credentials `json:"userData"`
	Posts       []*postData  `json:"posts"`
	DefaultTags []string     `json:"defaultTags"`
	Tags        []string     `json:"tags"`
	Number      string       `json:"pageNumber,number"`
	Thread      *threadData
	PageNumber  int
	PageName    string
	UserView    string
}

// threadData is part of pageData and is used to display a single thread or
// thread information
type threadData struct {
	Thread   *postData
	Children []*postData
	Parent   string
}

// postData is used in pageData and threadData and contains all the information
// for a single post or reply
type postData struct {
	Title  string        `json:"title"`
	Body   template.HTML `json:"body"`
	ID     string        `json:"ID"`
	Author string        `json:"author"`
	Parent string        `json:"parent"`
	TS     string        `json:"timestamp"`
	Tags   []string      `json:"tags"`
	// Type   string        `json:"postType"`
	// TODO: make password environment variable
	Testing  string `json:"testing"`
	Children []*postData
}

// ckey/ctxkey is used as the key for the HTML context and is how we retrieve
// token information and pass it around to handlers
type ckey int

const (
	ctxkey ckey = iota
)

var (
	// NOTE: The following two variables are initiated through your
	// operating system environment variables and are required for
	// TagMachine to work properly

	// hmacss=hmac_sample_secret
	// testPass=testingPassword

	// hmacSampleSecret is used for creating the token
	hmacSampleSecret = []byte(os.Getenv("hmacss"))

	// testPass is used only for testing, must be at least 10 characters
	testPass = getSecret()

	// connect to redis
	redisIP = os.Getenv("redisIP")
	rdb     = redis.NewClient(&redis.Options{
		Addr:     redisIP + ":6379",
		Password: "",
		DB:       0,
	})

	// HTML templates. We use them like components and compile them
	// together at runtime.
	templates = template.Must(template.New("main").ParseGlob("internal/*/*.tmpl"))
	// posts is used when someone views user posts or a set of posts with
	// certain tag(s).
	posts = make(map[string][]*postData)
	// frontpage is unique and used when a user views the "frontpage",
	// which is all the tags together.
	frontpage = make(map[string][]*postData)
	// auxiliary tags to be added in the init.go file
	tags        = []string{}
	defaultTags = []string{"politics", "stem", "arts", "other", "business", "sports"}
	// this context is used for the client/server connection. It's useful
	// for passing the token/credentials around.
	ctx = context.Background()
)

// This initializer runs before main()
func init() {
	// see: init.go
	beginCache()
}

func main() {
	fmt.Println(string(hmacSampleSecret))
	// Ping redis to make sure its up
	fmt.Println("Sending Ping() to redis")
	rs, err := rdb.Ping(ctx).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(rs)

	// This allows us to use rand throughout the app as necessary for
	// creating random data (Ex. generating post ID's).
	rand.Seed(time.Now().UTC().UnixNano())

	// Instantiating the http multiplexer and defining our routes
	mux := http.NewServeMux()
	mux.Handle("/", checkAuth(http.HandlerFunc(home)))
	mux.Handle("/user/", checkAuth(http.HandlerFunc(userPosts)))
	mux.Handle("/tag/", checkAuth(http.HandlerFunc(getTags)))
	mux.Handle("/view/", checkAuth(http.HandlerFunc(view)))
	mux.Handle("/rules/", checkAuth(http.HandlerFunc(rules)))
	mux.Handle("/api/newthread", checkAuth(http.HandlerFunc(newThread)))
	mux.Handle("/api/reply", checkAuth(http.HandlerFunc(newReply)))
	mux.HandleFunc("/api/signup", signup)
	mux.HandleFunc("/api/signin", signin)
	mux.HandleFunc("/api/logout", logout)
	mux.HandleFunc("/api/nextPage", nextPage)
	// This serves the /public directory holding public assets like css,
	// javascript, and images. HTML is not kept here.
	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))

	// Server configuration
	srv := &http.Server{
		// in production only ust SSL
		Addr:              ":9001",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       5 * time.Second,
	}

	// setting up our http context
	ctx, cancelCtx := context.WithCancel(context.Background())

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			fmt.Println(err)
		}
		cancelCtx()
	}()

	fmt.Println("Server started @ " + srv.Addr)
	<-ctx.Done()
}
