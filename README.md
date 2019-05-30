# passport-linkedin-oauth2-token

Token strategy for LinkedIn OAuth2 that supports `r_liteprofile` and `r_emailaddress` scopes.

## Install

```bash
$ npm i passport-linkedin-oauth2-token
```

## Usage

```js
var LinkedInTokenStrategy = require('passport-linkedin-oauth2-token').Strategy;
var passport = require('passport');

passport.use(
  new LinkedInTokenStrategy(
    {
      clientID: '<client id>',
      clientSecret: '<client secret>',
      scope: ['r_liteprofile', 'r_emailaddress'],
      
      // optionally pass req to callback
      passReqToCallback: true
    },
    function (req, accessToken, refreshToken, profile, done) {
      // asynchronous verification, for effect...
      process.nextTick(function () {
        // To keep the example simple, the user's LinkedIn profile is returned to
        // represent the logged-in user. In a typical application, you would want
        // to associate the LinkedIn account with a user record in your database,
        // and return that user instead.
        return done(null, profile);
      });
    }
  )
);
```
