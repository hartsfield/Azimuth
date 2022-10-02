// This is used to check if the URL contains any tags, as the tags are added 
// and removed dynamically as the user selects/deselects them. If they deselect
// all tags they are redirected to the front page.
// TODO: Find a better solution

var tags;
var localTags = localStorage.getItem("selectedTags");
if (localTags == null) {
    tags = [];
} else {
    tags = localTags.split(",");
}
if (window.location.href.includes("tags")) {
    // convert tags in the URL to an array of tags
    tags = (window.location.search.substring(window.location.search.indexOf("=")).substring(1).split(",").filter(v => v));
    // if there are no tags in the URL, and we're not showing an individual 
    // post ("Num=" would indicate that), redirect to the home page (show all 
    // posts)
    if (window.location.search.length > 0 && tags.length <= 0 && !window.location.href.includes("Num=")) {
        window.location = window.location.origin;
    }
}

// setTag is used to set the tags in the URL and highlight/de-highlight them on
// the client. A snippet of Javascript related to this is also found in 
// internal/components/colorshowtags.tmpl. It's been separted because that 
// portin of code needs to be run after the DOM loads. 
function setTag(tag) {
    if (tags.includes(tag)) {
        tags = tags.filter(x => x !== tag);
        window.location = window.location.origin + "/tag/?tags=" + tags.join(",");
        document.getElementById("tag_" + tag).style.backgroundColor = "#d52e12";
        localStorage.setItem("selectedTags", tags);
    } else {
        tags.push(tag);
        window.location = window.location.origin + "/tag/?tags=" + tags.join(",");
        document.getElementById("tag_" + tag).style.backgroundColor = "rgb(145, 186, 3)";
        document.getElementById("tag_" + tag).classList.add("selectedTag");
        localStorage.setItem("selectedTags", tags);
    }
}

// sets the username in user.tmpl 
// see: user.tmpl
var loc = window.location.pathname.split("/");
var uname = loc[loc.length - 1];

// This is used to show/hide the trending tags, and change the text in the 
// trending button.
// TODO: Possible re-write with a <div> around the non-default tags so I don't 
// have to use the loop, but only if it remains seamless.
var isTrendshowing = false;

function showTrending() {
    if (isTrendshowing == false) {
        document.getElementById("showTags").innerHTML = "[LESS]";
        var elms = document.getElementsByClassName("trending");
        for (var i = 0; i < elms.length; i++) {
            elms[i].style.display = "inline-flex";
        }
        isTrendshowing = true;
    } else {
        document.getElementById("showTags").innerHTML = "TRENDS ➡";
        var elms2 = document.getElementsByClassName("trending");
        for (var k = 0; k < elms2.length; k++) {
            elms2[k].style.display = "none";
        }

        isTrendshowing = false;
    }
}

// function slideOutAnimation() {
//     var nav = document.getElementById("mainNav");
//     nav.style.padding = "0";
//     document.getElementById("closeNav").style.display = "none";
//     var num;
//     var interval = setInterval(function() {
//         num = parseInt(nav.style.width);
//         num -= 3;
//         nav.style.width = num + "px";
//         if (num <= 0) {
//             nav.style.right = "-2em";
//             clearInterval(interval);
//         }
//     }, 1);
//     interval();
// }

// function slideInAnimation() {
//     var nav = document.getElementById("mainNav");
//     nav.style.padding = "1em";
//     document.getElementById("closeNav").style.display = "block";
//     var num;
//     var interval = setInterval(function() {
//         num = parseInt(nav.style.width);
//         num += 3;
//         nav.style.width = num + "px";
//         if (num >= 300) {
//             nav.style.right = "0px";
//             clearInterval(interval);
//         }
//     }, 1);
//     interval();
// }

// showLogin is used to show/hide the login form.
function showLogin() {
    if (document.getElementById("loginForm").style.display == "none") {
        document.getElementById("loginForm").style.display = "inline-flex";
    } else {
        document.getElementById("loginForm").style.display = "none";
    }
}

// showPostForm is used to show/hide the new post form. If the user already has
// selected tags, they're added to the tag input field.
function showPostForm() {
    if (isTrendshowing == true) {
        document.getElementById("showTags").innerHTML = "TRENDS ➡";
        var elms2 = document.getElementsByClassName("trending");
        for (var k = 0; k < elms2.length; k++) {
            elms2[k].style.display = "none";
        }
        isTrendshowing = false;
    }
    if (document.getElementById("newPostForm").style.display == "none") {
        document.getElementById("newPostForm").style.display = "block";
        if (tags.length >= 1) {
            document.getElementById("taginput").value = "#" + tags.join(", #");
        }
    } else {
        document.getElementById("newPostForm").style.display = "none";
        document.getElementById("taginput").value = "";
    }
}

// showReplyForm is used to show/hide the reply form, and change the text in 
// the button.
function showReplyForm(id) {
    if (document.getElementById("replyForm_" + id).style.display == "none") {
        document.getElementById("replyForm_" + id).style.display = "unset";
        document.getElementById("showReplyFormButt_" + id).innerHTML = "✖";
    } else {
        document.getElementById("replyForm_" + id).style.display = "none";
        document.getElementById("showReplyFormButt_" + id).innerHTML = "+ REPLY";
    }
}

// viewContext takes the user to the context of the post they're viewing 
// (usually the parent post).
function viewContext(parentID) {
    window.location = window.location.origin + "/view/?postNum=" + parentID;
}

// viewUser takes the user to a users profile.
function viewUser(user) {
    window.location = window.location.origin + "/user/" + user;
}

// auth is used for signing up and signing in/out. path could be:
// /api/signup
// /api/signin
// /api/logout
function auth(path) {
    var xhr = new XMLHttpRequest();

    xhr.open("POST", "/api/" + path);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onload = function() {
        if (xhr.status === 200) {
            var res = JSON.parse(xhr.responseText);
            if (res.success == "false") {
                // If we aren't successful we display an error.
                document.getElementById("errorField").innerHTML = res.error;
            } else {
                // Reload the page now that the user is signed in.
                window.location.reload();
            }
        }
    };

    // For now, all we're sending is a username and password, but we may start
    // asking for email or mobile number at some point.
    xhr.send(JSON.stringify({
        password: document.getElementById("password").value,
        username: document.getElementById("username").value,
    }));
}

// postThread posts a thread to a tag or set of tags.
function postThread(id) {
    var titlearea = document.getElementById("postTitle").value;
    var textarea = document.getElementById("postBody").value;
    var tagarea = document.getElementById("taginput").value;
    if (tagarea.length <= 3 || textarea.length <= 5 || titlearea.length <= 2) {
        document.getElementById("postButt").innerHTML = "No input field can be blank";
    } else {
        var xhr = new XMLHttpRequest();

        xhr.open("POST", "/api/newthread");
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onload = function() {
            if (xhr.status === 200) {
                var res = JSON.parse(xhr.responseText);
                if (res.success == "false") {
                    // If we aren't successful we display an error.
                    // TODO: Better error message
                    document.getElementById("postButt").innerHTML = "error";
                } else {
                    document.getElementById("newPostForm").style.display = "none";
                    window.location = window.location.origin + "/view/?postNum=" + res.postID;
                }
            }
        };
        var newTags = tagarea.match(/[^\s,]+/g);
        xhr.send(JSON.stringify({
            title: document.getElementById("postTitle").value,
            body: document.getElementById("postBody").value,
            tags: newTags,
        }));
    }
}

// reply is used to reply to a post.
function reply(id, parent) {
    var xhr = new XMLHttpRequest();

    xhr.open("POST", "/api/reply");
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onload = function() {
        if (xhr.status === 200) {
            var res = JSON.parse(xhr.responseText);
            if (res.success == "true") {
                window.location = window.location.origin + "/view/?postNum=" + id;
            } else {
                document.getElementById("replyError_" + id).innerHTML = res.error;
            }
        }
    };

    xhr.send(JSON.stringify({
        body: document.getElementById("replyBody_" + id).value,
        ID: id,
        // parent: parent,
    }));
}

function showContact() {
    document.getElementById("contactButt").style.textTransform = "unset"
    document.getElementById("contactButt").innerHTML = "TeleSoftEngineering@gmail.com";
}

function showCode() {
    document.getElementById("donateButt").innerHTML = "Coming Soon!";
}

function showRules() {
    window.location = window.location.origin + "/rules";
}

function fold(postID) {
    if (document.getElementById("folder_" + postID).style.display == "block") {
        document.getElementById("foldup_" + postID).innerHTML = "[+]";
        document.getElementById("folder_" + postID).style.display = "none";
    } else {
        document.getElementById("foldup_" + postID).innerHTML = "[-]";
        document.getElementById("folder_" + postID).style.display = "block";
    }
}

function goHome() {
    window.location = window.location.origin;
}

// var observer;

// var called = false;

function nextPage(lastPageNumber, pageName) {
    var e = document.getElementById("posts");
    var xhr = new XMLHttpRequest();


    xhr.open("POST", "/api/nextPage");
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onload = function() {
        if (xhr.status === 200) {
            var res = JSON.parse(xhr.responseText);
            if (res.success == "true") {
                e.insertAdjacentHTML("beforeend", res.template);
                var observer2 = new IntersectionObserver((entries) => {
                    entries.forEach((entry) => {
                        if (entry.intersectionRatio > 0) {
                            nextPage(res.pageNumber, res.PageName);
                            observer2.unobserve(document.querySelector("#loadScroll"))
                        }
                    });
                });

                observer2.observe(document.querySelector("#loadScroll"));

                for (var tag in tags) {
                    document.getElementById("tag_" + tags[tag]).style.backgroundColor = "#91ba03";
                    document.getElementById("tag_" + tags[tag]).style.color = "rgb(255 254 183)";
                    document.getElementById("tag_" + tags[tag]).style.border = "1px solid #6aa753";
                    var threads = document.getElementsByClassName("threadTag_" + tags[tag]);
                    for (var i = 0; i < threads.length; i++) {
                        var selectedId = threads[i].getAttribute("id");
                        document.getElementById(selectedId).style.backgroundColor = "91ba03";
                    }
                }
                if (tags.length > 0) {
                    isTrendshowing = false;
                    showTrending();
                } else {
                    isTrendshowing = true;
                    showTrending();
                }

            }
        }
    };

    if (tags.length > 0) {
        if (tags.length == 1 && tags[0].length == 0) {
            pageName = "frontpage";
        } else {
            pageName = "hasTags";
        }
    } else {
        pageName = "frontpage";
    }

    xhr.send(JSON.stringify({
        pageNumber: lastPageNumber,
        pageName: pageName,
        tags: tags,
    }));
}
