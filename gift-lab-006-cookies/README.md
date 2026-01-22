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
## Lesson
- This lab shows the danger of weak tokens
  - A base64 token is created on login with the format `bugforge-3_letter_suffix`
- The student can fuzz the application and find the endpoint `/administrator`
- The student needs to decode the session token
  - find out through `sequencer`that only the suffix changes
  - create a bruteforce attack on `/administrator`
  - The base64 decoded string is `bugforge-rls` or in encoded form: `YnVnZm9yZ2Utcmxz`
- Access `/administrator` once the token is valid and read the flag.

