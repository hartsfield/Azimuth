package main

import (
	"fmt"
	"time"
)

// init.go contains funtions used to initialize data for TagMachine.

// lastCached was when the database was last cached
var lastCached time.Time

// beginCache will cache the database no more than every 3 seconds. This
// function is run on startup, and when a post or reply is added to the
// database. In the event that many posts are being posted at once, the
// function is designed to only rebuild the cache every 3 seconds. This could
// be adjusted if needed.
func beginCache() {
	if time.Now().Sub(lastCached).Milliseconds() > 3000 {
		fmt.Println("caching")
		lastCached = time.Now()
		// Race condition(?) prevention. Say we have two users posting
		// consecutively. User_1 submits a post and this triggers a
		// rebuild of the cache. User_2 submits a post 1 second later.
		// If we didn't have this delay, the User_2's post would not
		// get cached, because the rebuild triggered by User_1 would
		// have already started.
		// By delaying the rebuild for 3.5 seconds we insure
		// all posts are cached, even those that don't trigger a
		// re-cache automatically.
		time.AfterFunc(3500*time.Millisecond, func() { getData() })
	}
}

// func trimDB() {
// 	_, err := rdb.ZRevRange(ctx, ALLPOSTS)
// }

// getData gets the board data from redis, including the tags and posts. This
// is used to initialize tagmachine with data, and to update the cached data in
// the "posts" and "frontpage" maps, and the "tags" slice.
func getData() {
	// posts will be used to store the posts for each tag
	// Ex. posts["politics"][]postData{}, it's also defined as a global,
	// but needs to be redefined here for use in an init() function. There
	// may be a cleaner way to do this.
	posts = make(map[string][]*postData)

	// Get all the members of "TAGS" (all the tags in our database)
	tagmem, err := rdb.ZRevRange(ctx, "TAGS", 0, -1).Result()
	handleErr(err)

	tags = []string{} // global used after we filter out the default tags
	for _, tag := range tagmem {
		// Only getting non-default tags, we already know the default
		// tags
		if !isDefaultTag(tag) {
			tags = append(tags, tag)
		}
		// Get the postIDs associated with the tag
		dbPosts, err := rdb.ZRevRange(ctx, tag, 0, -1).Result()
		handleErr(err)

		// Get the posts using the postIDs
		for _, post := range dbPosts {
			data, err := rdb.HGetAll(ctx, "OBJECT:"+post).Result()
			handleErr(err)

			posts[tag] = append(posts[tag], makePost(data, false))
		}
	}

	// frontpage contains all the posts in the database. Also defined
	// globally, but needs to be redefined here for use in init()
	frontpage = make(map[string][]*postData)
	dbPosts, err := rdb.ZRevRange(ctx, "ALLPOSTS", 0, -1).Result()
	handleErr(err)

	for _, dbPost := range dbPosts {
		data, err := rdb.HGetAll(ctx, "OBJECT:"+dbPost).Result()
		handleErr(err)

		frontpage["all"] = append(frontpage["all"], makePost(data, false))
	}

}
