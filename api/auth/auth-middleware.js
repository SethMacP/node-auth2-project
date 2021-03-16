const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets"); // use this secret!
const model = require('../users/users-model')

const restricted = () => async(req, res, next) => {
    try{
      const token = req.headers.auth;
      if(!token){
        return res.status(401).json({message:"Token required"})
      }
      console.log("3")
      jwt.verify(token, JWT_SECRET, (err,decoded)=>{
          if(err){
              return res.status(401).json({message:"Token Invalid"})
          }
          req.token = decoded;
        })
        next();
    }catch(err){
      next(err)
    }

  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => {
    const token = req.token
    console.log('my token',token.role_name)
    console.log('role_name', role_name)
    if(token.role_name !== role_name){
        res.status(403).json({message:"This is not for you"})
    }
    next();
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = () =>async (req, res, next) => {
    try{
        const {username} = req.body
        console.log(username)
        const checkDatabase = await model.findBy({username})
        
        if(!checkDatabase){
            return res.status(401).json({message:"Invalid credentials"})
        }
        next();
    }catch(err){
        next(err)
    }
  
    /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = () => async(req, res, next) => {
    // console.log(req.body)
    //If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.
    if(req.body.role_name){
        req.role_name = req.body.role_name.trim();
    }
    //If role_name is missing from req.body, or if after trimming it is just an empty string, 
    //set req.role_name to be 'student' and allow the request to proceed.
    // console.log("length: ", req.role_name.length);
    if(!req.body.role_name || req.role_name.length === 0){
        // console.log("req.body.role_name1", req.body.role_name)
        // console.log("req.role_name2", req.role_name)
        req.role_name = 'student'
    }
    /*If role_name is 'admin' after trimming the string:
    status 422
        {"message": "Role name can not be admin"}
    */
//    console.log('req.role_name', req.role_name)
    if(req.role_name == 'admin'){
        return res.status(422).json({message:"Role name can not be admin"})
    }
    /*
    If role_name is over 32 characters after trimming the string:
    status 422
    {"message": "Role name can not be longer than 32 chars"}
  */
    if(req.role_name.length >32){
        return res.status(422).json({message:"Role name can not be longer than 32 chars"})
    }

    next();


    
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
