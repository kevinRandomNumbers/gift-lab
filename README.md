# Gift lab
This is a lab that allows me to explore making vulnerable labs as part of my Web AppSec Journey.
## Purpose
The purpose of the app is that a user can create lists for gift ideas. Those gift lists then can be shared with other users.
## Installation
To run the lab simply run `nmp install`.

After the node_modules have been installed, you can run the app with `node server.js`

Run `npm run dev` if you need nodemon.
## How to use it
- If you want to learn black box testing, run the app and hack away.
- Should you want to do code review, all code is available :)
## Users
- `admin:pass`
- `jeremy:cheesecake`
## Remarks
- Please note that the database is in memory, so all data is lost after the application has been closed.
- **This is a work in progress, noise in the responses, unintended vulns are part of my journey and I promise to make it as good as possible.**
- You are free to use, edit this application as you wish.
### What does the app do now
- I updated bit of the AI generated code, yes I know, big mistake but that's how we learn. Like is said, it's a work in progress.
- Log in feature where a `user_id` cookie is set, this cookie is used to fetch the list(s) in de SQLite db.
- Once your lists are loaded in `\dashboard`, you can click it to go to `\list\:id`
- On `\list\:id` you can add something on the list.
### Known vulns
- IDOR, users can see each other lists.

