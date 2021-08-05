const express = require('express');
const { check, validationResult } = require('express-validator');

const db = require('../db/models');
const { csrfProtection, asyncHandler } = require('./utils');
const bcryptjs = require('bcryptjs');

const router = express.Router();

const userValidators = [
    check('firstName')
    .exists({checkFalsy: true})
    .withMessage('Please enter a first name')
    .isLength({max:50})
    .withMessage('First name must be shorter than 50 characters'),
    check('lastName')
    .exists({checkFalsy: true})
    .withMessage('Please enter a last name')
    .isLength({max:50})
    .withMessage('Last name must be shorter than 50 characters'),
    check('emailAddress')
    .exists({checkFalsy: true})
    .withMessage('Please enter an email address')
    .isLength({max:255})
    .withMessage('Email must be shorter than 255 characters')
    .normalizeEmail().isEmail()
    .withMessage('Please provide a valid email address')
    .custom(value => {
        return db.User.findOne({where: { emailAddress: value } }).then(user => {
          if (user) {
            return Promise.reject('E-mail already in use');
          }
        });
      }),
    check('password').exists({ checkFalsy: true })
    .withMessage('Please enter a password')
    .isLength({max: 50})
    .withMessage('Must be less than 50 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/, 'g')
    .withMessage('Password must contain at least 1 lowercase letter, uppercase letter, number, and special character (i.e. "!@#$%^&*")'),
    check('confirmPassword').exists({ checkFalsy: true })
    .withMessage('Please confirm your password')
    .isLength({ max: 50 })
    .withMessage('Password confirmation must not be more than 50 characters long')
    .custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Password confirmation does not match');
    }
    return true;
  }),
]



router.get('/user/register', csrfProtection, asyncHandler(async (req, res) => {
    const user = db.User.build();
    res.render('user-register', {
        title: 'Register Here',
        user,
        csrfToken: req.csrfToken(),
    });
}));

router.post('/user/register', csrfProtection,
userValidators,
asyncHandler(async (req, res) => {
    const { emailAddress, firstName, lastName, password, confirmPassword } = req.body;

    console.log(emailAddress, firstName, lastName, password, confirmPassword)

    const user = db.User.build({emailAddress, firstName, lastName});

    const validatorErrors = validationResult(req);

    console.log('errors', validatorErrors.errors);

    if (validatorErrors.errors.length > 0 ) {
        const errorsArray = validatorErrors.array().map((error) => error.msg);
        res.render('user-register', {
            title: 'Register Here',
            user,
            errorsArray,
            csrfToken: req.csrfToken(),
          });
        }

    const hashedPassword = bcryptjs.hashSync(password, 10);
        user.hashedPassword = hashedPassword;
        await user.save();
        res.redirect('/');
}));

module.exports = router;
