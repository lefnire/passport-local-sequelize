'use strict';
const util = require('util'),
  crypto = require('crypto'),
  _ = require('lodash'),
  Sequelize = require('sequelize'),
  LocalStrategy = require('passport-local').Strategy;

// The default option values
let defaultAttachOptions = {
  activationkeylen: 8,
  resetPasswordkeylen: 8,
  saltlen: 32,
  iterations: 12000,
  keylen: 512,
  usernameField: 'username',
  usernameLowerCase: false,
  activationRequired: false,
  hashField: 'hash',
  saltField: 'salt',
  activationKeyField: 'activationKey',
  resetPasswordKeyField: 'resetPasswordKey',
  incorrectPasswordError: 'Incorrect password',
  incorrectUsernameError: 'Incorrect username',
  invalidActivationKeyError: 'Invalid activation key',
  invalidResetPasswordKeyError: 'Invalid reset password key',
  missingUsernameError: 'Field %s is not set',
  missingFieldError: 'Field %s is not set',
  missingPasswordError: 'Password argument not set!',
  userExistsError: 'User already exists with %s',
  activationError: 'Email activation required',
  noSaltValueStoredError: 'Authentication not possible. No salt value stored in db!'
};

// The default schema used when creating the User model
let defaultUserSchema = {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  username: {
    type: Sequelize.STRING,
    allowNull: false,
    unique: true
  },
  hash: {
    type: Sequelize.TEXT,
    allowNull: false
  },
  salt: {
    type: Sequelize.STRING,
    allowNull: false
  },
  activationKey: {
    type: Sequelize.STRING,
    allowNull: true
  },
  resetPasswordKey: {
    type: Sequelize.STRING,
    allowNull: true
  },
  verified: {
    type: Sequelize.BOOLEAN,
    allowNull: true
  }
};

let attachToUser = function(UserSchema, options) {
  // Get our options with default values for things not passed in
  options = _.defaults(options || {}, defaultAttachOptions);

  UserSchema.beforeCreate(function(user, op, next) {
    // if specified, convert the username to lowercase
    if (options.usernameLowerCase) {
      user[options.usernameField] = user[options.usernameField].toLowerCase();
    }
    if (typeof(next) === 'function') {
      next(null, user);
    }
  });

  UserSchema.Instance.prototype.setPassword = function(password, cb) {
    if (!password) {
      return cb(new Error(options.missingPasswordError));
    }

    crypto.randomBytes(options.saltlen, (err, buf) => {
      if (err) return cb(err);
      let salt = buf.toString('hex');
      crypto.pbkdf2(password, salt, options.iterations, options.keylen, (err, hashRaw) => {
        if (err) return cb(err);
        this.set(options.hashField, new Buffer(hashRaw, 'binary').toString('hex'));
        this.set(options.saltField, salt);
        cb(null, this);
      });
    });
  };

  UserSchema.Instance.prototype.setActivationKey = function(cb) {
    if (!options.activationRequired)
      return cb(null, this);
    crypto.randomBytes(options.activationkeylen, (err, buf) => {
      if (err) return cb(err);
      let randomHex = buf.toString('hex');
      this.set(options.activationKeyField, randomHex);
      cb(null, this);
    });
  };

  UserSchema.Instance.prototype.authenticate = function(password, cb) {
    // prevent to throw error from crypto.pbkdf2
    if (!this.get(options.saltField))
      return cb(null, false, {message: options.noSaltValueStoredError});
    // TODO: Fix callback and behavior to match passport
    crypto.pbkdf2(password, this.get(options.saltField), options.iterations, options.keylen, (err, hashRaw) => {
      if (err) return cb(err);
      let hash = new Buffer(hashRaw, 'binary').toString('hex');
      if (hash === this.get(options.hashField)) {
        return cb(null, this);
      } else {
        return cb(null, false, {message: options.incorrectPasswordError});
      }
    });
  };

  UserSchema.authenticate = function() {
    return (username, password, cb) => {
      this.findByUsername(username, (err, user) =>
        err ? cb(err)
          : user ? user.authenticate(password, cb)
          : cb(null, false, {message: options.incorrectUsernameError})
      );
    };
  };

  UserSchema.serializeUser = function() {
    return (user, cb) => cb(null, user.get(options.usernameField));
  };

  UserSchema.deserializeUser = function() {
    return (username, cb) => this.findByUsername(username, cb);
  };

  UserSchema.register = function(user, password, cb) {
    let fields = {};

    if (user instanceof UserSchema.Instance) {
      // Do nothing
    } else if (_.isString(user)) {
      // Create an instance of this in case user is passed as username
      fields[options.usernameField] = user;
      user = this.build(fields);
    } else if (_.isObject(user)) {
      // Create an instance if user is passed as fields
      user = this.build(user);
    }

    if (!user.get(options.usernameField)) {
      return cb(new Error(util.format(options.missingUsernameError, options.usernameField)));
    }

    this.findByUsername(user.get(options.usernameField), (err, existingUser) => {
      if (err) return cb(err);
      if (existingUser) {
        return cb(new Error(util.format(options.userExistsError, user.get(options.usernameField))));
      }
      user.setPassword(password, (err, user) => {
        if (err) return cb(err);
        user.setActivationKey((err, user) => {
          if (err) return cb(err);
          user.save().then(() => cb(null, user)).catch(err => cb(err));
        });
      });
    });
  };

  UserSchema.activate = function(username, activationKey, cb) {
    this.findByUsername(username, (err, user, info) => {
      if (err) return cb(err);
      if (!user) return cb(info);
      if (user.get(options.activationKeyField) === activationKey) {
        user.updateAttributes({verified: true, activationKey: 'null'})
          .then(() => cb(null, user)).catch(err => cb(err));
      } else {
        return cb({message: options.invalidActivationKeyError});
      }
    });
  };

  UserSchema.findByUsername = function(username, cb) {
    let queryParameters = {};

    // if specified, convert the username to lowercase
    if (options.usernameLowerCase) {
      username = username.toLowerCase();
    }

    queryParameters[options.usernameField] = username;

    let query = this.find({where: queryParameters});
    if (options.selectFields) {
      query.select(options.selectFields);
    }
    query.then(user => cb(null, user)).catch(err => cb(err));
  };

  UserSchema.setResetPasswordKey = function(username, cb) {
    this.findByUsername(username, (err, user) => {
      if (err) return cb(err);
      if (!user) return cb({message: options.incorrectUsernameError});
      crypto.randomBytes(options.resetPasswordkeylen, (err, buf) => {
        if (err) return cb(err);
        let randomHex = buf.toString('hex');
        user.set(options.resetPasswordKeyField, randomHex);
        user.save().then(() => cb(null, user)).catch(err => cb(err));
      });
    });
  };

  UserSchema.resetPassword = function(username, password, resetPasswordKey, cb) {
    this.findByUsername(username, (err, user) => {
      if (err) return cb(err);
      if (user.get(options.resetPasswordKeyField) === resetPasswordKey) {
        user.setPassword(password, (err, user) => {
          if (err) return cb(err);
          user.set(options.resetPasswordKeyField, null);
          user.save().then(() => cb(null, user)).catch(err => cb(err));
        });
      } else {
        return cb({message: options.invalidResetPasswordKeyError});
      }
    });
  };

  UserSchema.createStrategy = function() {
    return new LocalStrategy(options, this.authenticate());
  };
};

let defineUser = function(sequelize, extraFields, attachOptions) {
  let schema = _.defaults(extraFields || {}, defaultUserSchema);
  let User = sequelize.define('User', schema);
  attachToUser(User, attachOptions);
  return User;
};

module.exports = {
  defaultAttachOptions,
  defaultUserSchema,
  attachToUser,
  defineUser
};
