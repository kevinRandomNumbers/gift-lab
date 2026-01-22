# Gift lab
This is a lab that allows me to explore making vulnerable labs as part of my Web AppSec Journey.
## Purpose
The purpose of the app is that a user can create lists for gift ideas. Those gift lists then can be shared with other users.
## Installation
- To run the app on docker, just run `docker-compose up --build`
- To run the with node run `npm install`.
    - After the node_modules have been installed, you can run the app with `node server.js`
- Run `npm run dev` if you need nodemon.
## How to use it
- If you want to learn black box testing, run the app and hack away.
- Should you want to do code review, all code is available :)
## Hint
Security through obscurity is **not** security.
### Walkthrough
- When a user clicks the `share` button, a token is generated and stored in the database.
- This token consists out of two parts:
  - The base string `listWithId-`
  - The suffix which is the ID of the list.
- This string is Base64 encoded.
- A player must discover the Base64 nature of the share token.
- "Decrypt" it.
- Create their own Base64 encoded `listWithId-1`
- See the flag on the Admin's B-day list.

