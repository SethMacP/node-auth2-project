const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const model = require('../users/users-model')
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs')


router.post("/register", validateRoleName(), async(req, res, next) => {
  try{
    //Grab the items that you want to register with
    const {username, password} = req.body;
    const role_name = req.role_name
    //Verify the user doesn't exist
    const user = await model.findBy({username})
    //findBy returns an array
    if(user && user.length >= 1){
      return res.status(409).json({
        message:"Username already taken"
      })
    }
    //Build the object for the new user & hash the password
    const newUser = await model.add({
      username,
      password: await bcrypt.hash(password, 10),
      role_name
    })
    //On success
    res.status(201).json(newUser);

  }catch(err){
    next(err);
  }
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
});

//
router.post("/login", checkUsernameExists(),  async(req, res, next) => {
  try{
        const {username, password} = req.body;
        //check to see if its a valid username
        const user = await model.findBy({username})
        if(!user){
            return res.status(418).json({message:"User does not exist"})
        }
        //check to see if the hashes match
    console.log("req.body.password:", req.body.password)
    console.log('user.passowrd', user.password)
        const passwordValidation = await bcrypt.compare(password, user.password)
        if(passwordValidation === false){
            return res.status(401).json({message:"Invalid credentials"})
        }
        //create the token
        const token = jwt.sign({
            subject: user.user_id,
            username: user.username,
            role_name: user.role_name,
            expiresIn: '24h'
        }, JWT_SECRET)
        
        //create the cookie (name it, provide it value)
        res.cookie("token", token)
        //success!
        res.json({
            message:`Welcome ${user.username}`,
            token: token
        })
  }catch(err){
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
