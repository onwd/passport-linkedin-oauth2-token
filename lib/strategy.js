var util = require('util');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;

function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://www.linkedin.com/oauth/v2/authorization';
  options.tokenURL = options.tokenURL || 'https://www.linkedin.com/oauth/v2/accessToken';
  options.scope = options.scope || ['r_liteprofile'];
  options.profileFields = options.profileFields || null;

  options.customHeaders = options.customHeaders || { 'x-li-format': 'json' };
  this._passReqToCallback = options.passReqToCallback;

  OAuth2Strategy.call(this, options, verify);

  this.options = options;
  this.name = 'linkedin-token';
  this.profileUrl = 'https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))';
  this.emailUrl = 'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))';
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    return this.fail();
  }

  var accessToken, refreshToken;

  if (req.body) {
    accessToken = req.body.access_token;
    refreshToken = req.body.refresh_token;
  }

  accessToken = accessToken || req.query.access_token || req.headers.access_token;
  refreshToken = refreshToken || req.query.refresh_token || req.headers.refresh_token;

  if (!accessToken) {
    return this.fail();
  }

  self.userProfile(accessToken, function(err, profile) {
    if (err) {
      return self.fail(err);
    };

    function verified(err, user, info) {
      if (err) {
        return self.error(err);
      }
      if (!user) {
        return self.fail(info);
      }
      self.success(user, info);
    }

    if (self._passReqToCallback) {
      self._verify(req, accessToken, refreshToken, profile, verified);
    } else {
      self._verify(accessToken, refreshToken, profile, verified);
    }
  });
};

Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.setAccessTokenName('oauth2_access_token');

  var profile = { provider: 'linkedin' };
  var loadedProfile = false;
  var loadedEmail = false;
  var cbCalledWithError = false;

  this._oauth2.get(this.profileUrl, accessToken, function(err, body, res) {
    try {
      if (err) {
        throw new InternalOAuthError('failed to fetch user profile', err);
      }

      var json = JSON.parse(body);

      profile.id = json.id;

      var firstName = json.firstName.localized[Object.keys(json.firstName.localized)[0]];
      var lastName = json.lastName.localized[Object.keys(json.lastName.localized)[0]];

      profile.name = {
        givenName: firstName,
        familyName: lastName
      };

      profile.displayName = firstName + ' ' + lastName;

      if (
        json.profilePicture &&
        json.profilePicture['displayImage~'] &&
        json.profilePicture['displayImage~'].elements &&
        json.profilePicture['displayImage~'].elements.length > 0
      ) {
        profile.photos = json.profilePicture['displayImage~'].elements.reduce(function(memo, el) {
          if (el && el.identifiers && el.identifiers.length > 0) {
            memo.push({ value: el.identifiers[0].identifier });
          }
          return memo;
        }, []);
      }

      profile._profileRaw = body;
      profile._profileJson = json;

      loadedProfile = true;

      if (!this.options.scope.includes('r_emailaddress')) {
        loadedEmail = true;
      }

      if (loadedEmail) {
        return done(null, profile);
      }
    } catch(e) {
      if (!cbCalledWithError) {
        cbCalledWithError = true;
        done(e);
      }
    }
  }.bind(this));

  if (this.options.scope.includes('r_emailaddress')) {
    this._oauth2.get(this.emailUrl, accessToken, function(err, body, res) {
      try {
        if (err) {
          throw new InternalOAuthError('failed to fetch user email', err);
        }

        var json = JSON.parse(body);

        if (
          json.elements &&
          json.elements.length > 0
        ) {
          profile.emails = json.elements.reduce(function(memo, el) {
            if (el['handle~'] && el['handle~'].emailAddress) {
              memo.push({
                value: el['handle~'].emailAddress
              });
            }
            return memo;
          }, []);
        }

        profile._emailRaw = body;
        profile._emailJson = json;

        loadedEmail = true;

        if (loadedProfile) {
          done(null, profile);
        }
      } catch (e) {
        if (!cbCalledWithError) {
          cbCalledWithError = true;
          done(e);
        }
      }
    }.bind(this));
  }
};

Strategy.prototype.authorizationParams = function(options) {
  var params = {};
  if (options.state) {
    params.state = options.state;
  }
  return params;
};

module.exports = Strategy;
