const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    
    const User = {
      username: req.body.username,
      password: await bcrypt.hash(req.body.password, 10),
      role_name: req.role_name
    }
    Users.add(User)
      .then(newUser => {
        res.status(201).json(newUser);
        return;
      })
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  let { username, password } = req.body;
  try {
    const [user] = await Users.findBy({ username })
    if(user && bcrypt.compareSync(password, user.password)){
      const payload = {
        subject: user.user_id,
        username: username,
        role_name: user.role_name
      };
      const token = jwt.sign(payload, JWT_SECRET, {expiresIn: '1d'});
      res.status(200).json({
        message: `${user.username} is back!`,
        token: token
      })
    } else {
      next({ status: 401, message: 'Invalid Credentials' })
    }
  } catch(err) {
    next(err);
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

});

module.exports = router;
