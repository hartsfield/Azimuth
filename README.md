# #TagMachine

NOTE: This program is still in alpha stages and is extremely unstable. Don't 
expect it to be bug free. 

TagMachine is a new type of social media website that aims to accept and 
embrace social media as a modern form of journalism. 

TagMachine requires Redis (6.0.16+) and has only been tested on Linux servers.

To run this program: 

* clone the repository and `cd` into the project directory
* Start redis (generally `redis-server &`)
* run this command with your personal environment variables for the `hmac` sample
secret and testing password:
</a>

    hmacss=YOUR_SECRET_PHRASE testPass=YOUR_TESTING_PASS go run .

This will start TagMachine but the website will fail to load until you add 
data. You can add test data using another progam I'm creating as a test suite 
called [TagBot](https://github.com/hartsfield/TagBot).

![tm](https://user-images.githubusercontent.com/30379836/192171321-90aafe05-25d3-4ea6-9d71-13336c0c1394.png)
