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
## Status lab
- This lab is vulnerable to XSS on the `/share` and `/list` page.
- A student will get visual feedback on the filter.
- Filter is not recursive, but will filter once on
  - `<img`
  - `<script>`
  - `<iframe`
  - `<svg`
  - `<body`
- Once the filter is bypassed, the payload will execute and the student gets the flag.

