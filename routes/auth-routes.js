const express = require('express');

const router = express.Router();

const User = require('../models/user-model');

//To encrypt the password we need to install and require BCRYPTJS
//npm i bcryptjs in terminal first
const bcrypt = require("bcryptjs");
const bcryptSalt = 10; 

router.get('/signup', (req, res, next)=> {
  res.render('auth/signup');
})


router.post('/signup', (req,res,next) => {
  //console.log(req.body);
  const userEmail = req.body.email;
  const userPassword = req.body.password;

  if( userEmail == '' || userPassword == ''){
    res.render('auth/signup', { errorMessage: 'Please provide both, email and password in order to create an account!'});
    return; // <== in order to avoid having huge else statement jsut enter return here to stop
  }

  User.findOne({ email: userEmail})
  .then( foundUser =>{
    if( foundUser !== null){
      res.render('auth/signup', { errorMessage: 'Sorry, an account with that email already exists'});
      return;
    }
    const salt  = bcrypt.genSaltSync(bcryptSalt);

    const hashPass = bcrypt.hashSync(userPassword, salt);
  
    User.create({
      //email and password are the keys from User model
      email: userEmail,
      password: hashPass
      //userEmai and hashPass are the one our user inputs(But password is encrypted with hashPass)
    })
    .then( newUser => {
      console.log("New User is: ", newUser);
      res.redirect('/');
    })
    .catch(err => console.log("error while creteing a new user", err));
  })
  .catch( err => console.log("Error while checking if user exists", err));
})

 

//LOGIN Route 

router.get('/login', (req, res, next)=> {
  res.render('auth/login');
})

router.post('/login', (req,res,next)=> {

  const userLoginEmail = req.body.email;
  const userLoginPassword = req.body.password;

  if( userLoginEmail == '' || userLoginPassword == ''){
    res.render('auth/login', { errorMessage: 'Please provide both, email and password in order to login'});
    return; // <== in order to avoid having huge else statement jsut enter return here to stop
  }
User.findOne ( { email: userLoginEmail})
.then( user => {
  if(!user){
    res.render('auth/login', { errorMessage: `User doesn't exist, please signup`});
    return;
  }
    //compareSync receives 2 arguments actual password from DB and user from above statement which is the one that was entered by user
    if(bcrypt.compareSync( userLoginPassword, user.password )){
      req.session.currentUser = user;
      res.redirect('/')
    } else {
      res.render('auth/login', { errorMessage: 'incorrect password!'})
    }
})
})


//Private page set up

router.use((req,res,next)=>{
  if(req.session.currentUser){
    next();
  } else {
    res.redirect('/login')
  }
})

router.get('/private', (req, res, next)=> {
  res.render('user-pages/private-page', { user: req.session.currentUser})
})

router.get('/logout', (req,res,next)=> {
  req.session.destroy( err => {
    console.log("Error while loggin out:", err);
    res.redirect('/login');
  })
})


module.exports = router;