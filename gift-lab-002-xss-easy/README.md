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
- This lab is vulnerable to an easy XSS (no filter, basic `<script>` or `<img>` will do).
- The vulnerability is only on the `share` page. This would make the most sense as you share that page with other people.


