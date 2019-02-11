(function (module) {
    "use strict";

    var User = require.main.require("./src/user"),
        meta = require.main.require("./src/meta"),
        db = require.main.require("./src/database"),
	      passport = require.main.require('passport'),
        passportLdap = require('passport-ldapauth').Strategy,
        fs = require.main.require('fs'),
        path = require.main.require('path'),
        nconf = require.main.require('nconf'),
        async = require.main.require('async'),
        winston = require.main.require('winston');

    var authenticationController = require.main.require('./src/controllers/authentication');
    
    var constants = Object.freeze({
        'name': "LDAP Account",
        'admin': {
            'route': '/plugins/sso-ldap',
            'icon': 'fa-user'
        }
    });

    var Ldap = {};

    Ldap.init = function (params, callback) {
        function render(req, res, next) {
            res.render('admin/plugins/sso-ldap', {});
        }
        console.log("sso-ldap starting");
        params.router.get('/admin/plugins/sso-ldap', params.middleware.admin.buildHeader, render);
        params.router.get('/api/admin/plugins/sso-ldap', render);

        callback();
    };

    Ldap.getStrategy = function (strategies, callback) {
        meta.settings.get('sso-ldap', function (err, settings) {
            //console.log("sso-ldap getStrategy: ", (!err && settings['server'] && settings['username'] && settings['secret'] && settings['base'] && settings['filter'] && settings['attributes'] && settings['searchAttributes']));
            console.log("sso-ldap getStrategy: ", settings['searchAttributes'] );
            if (!err && settings['server'] && settings['username'] && settings['secret'] && settings['base'] && settings['filter'] && settings['attributes'] && settings['searchAttributes']) {
                console.log("print debug", settings['server']);
                passport.use(new passportLdap({
                    server: {
                        url: settings['server']
                    },
                    usernameField: settings['username'],
                    passwordField: settings['secret'],
                    searchBase: (settings['base']).split(','),
                    /*search: {
                        filter: settings['filter'],
                        scope: 'sub',
                        attributes: (settings['attributes']).split(','),
                        sizeLimit: 1
                    },*/
                    searchFilter: settings['filter'],
                    searchAttributes: settings['searchAttributes']

                }, function (accessToken, refreshToken, profile, callback) {
                    Ldap.login(profile.id, profile.displayName, profile.emails[0].value, function (err, user) {
                        if (err) {
                            console.log("sso-ldap login error", err, new Error('sso-ldap').stack);
                            return callback(err);
                        } else {
                            console.log("sso-ldap login", user);
                        }
                        //return callback(null, user);
                        authenticationController.onSuccessfulLogin(req, user.uid, function (err) {
                          done(err, !err ? user : null);
                        });
                    });
                }));

                console.log("sso-ldap strategies pushing");

                strategies.push({
                    name: 'ldap',
                    url: '/auth/ldap',
                    callbackURL: '/auth/ldap/callback',
                    icon: 'fa-user',
                    scope: 'public_profile, email'
                });
                console.log("sso-ldap strategies pushed");
            }
            else {
                console.log("root error ", settings);
            }

            callback(null, strategies);
        });
    };

    Ldap.login = function (ldapId, handle, email, callback) {
        Ldap.getUidByLdapId(LdapId, function (err, uid) {
            if (err) {
                return callback(err);
            }

            if (uid !== null) {
                // Existing User
                return callback(null, {
                    uid: uid
                });
            } else {
                // New User
                var success = function (uid) {
                    // Save provider-specific information to the user
                    User.setUserField(uid, 'ldapid', ldapId);
                    db.setObjectField('ldapid:uid', ldapId, uid);
                    callback(null, {
                        uid: uid
                    });
                };

                return User.getUidByEmail(email, function (err, uid) {
                    if (err) {
                        return callback(err);
                    }

                    if (!uid) {
                        return User.create({username: handle, email: email}, function (err, uid) {
                            if (err) {
                                return callback(err);
                            }

                            return success(uid);
                        });
                    } else {
                        return success(uid); // Existing account -- merge
                    }
                });
            }
        });
    };

    Ldap.getUidByLdapId = function (ldapid, callback) {
        db.getObjectField('ldapid:uid', ldapid, function (err, uid) {
            if (err) {
                return callback(err);
            }
            return callback(null, uid);
        });
    };

    Ldap.addMenuItem = function (custom_header, callback) {
        custom_header.authentication.push({
            "route": constants.admin.route,
            "icon": constants.admin.icon,
            "name": constants.name
        });

        callback(null, custom_header);
    };

    module.exports = Ldap;
}(module));
