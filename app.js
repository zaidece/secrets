//jshint esversion:6
require('dotenv').config()
const express=require('express')
const bodyParser=require('body-parser')
const mongoose=require('mongoose')
// const encrypt=require('mongoose-encryption')
const ejs=require('ejs')
const session=require('express-session')
const passport=require('passport')
const passportLocalMongoose=require("passport-local-mongoose");
const app=express();
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-find-or-create')
var LocalStrategy    = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;

// const FacebookStrategy=require('passport-facebook')
// const md5=require('md5');
// const bcrypt=require('bcrypt')
// const saltRounds=10;
mongoose.set('strictQuery', true)
app.use(bodyParser.urlencoded({extended:true}))
app.use(express.static("public"))
app.set('view engine', 'ejs')
app.use(session({
  secret:"Our little Secret.",
  resave:false,
  saveUninitialized:false

}));
app.use(passport.initialize())
app.use(passport.session())
mongoose.connect("mongodb://127.0.0.1/userDB")
const userSchema=new mongoose.Schema({
  username:String,
  email:String,
  password:String,
  loginId:String,
  location:String,
  secret:String
})
userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)
// console.log(md5("123456"))
// console.log(process.env)
// userSchema.plugin(encrypt, { secret: process.env.SECRET,encryptedFields: ["password"] });
const User=new mongoose.model('User',userSchema)
passport.use(User.createStrategy())
passport.serializeUser(function(user, done) {
    done(null, user._id);
    // if you use Model.id as your idAttribute maybe you'd want
    // done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken,email, profile, cb) {
    // console.log(profile)
    User.findOrCreate({ username: profile.email,loginId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret:process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profilefields: ['id', 'displayName', 'photos', 'email','gender']
  },
  function(accessToken, refreshToken,email, profile, cb) {
    // console.log(profile)
    User.findOrCreate({ loginId: profile.id ,location:profile.user_location}, function (err, user) {
      return cb(err, user);
    });
  }
));
 app.get('/auth/facebook', passport.authenticate('facebook', { scope : ['email','user_location'] }));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {

    res.redirect('/secrets');
  });


app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));
  app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
app.get('/',function(req,res){
  res.render('home')

})
app.get('/login',function(req,res){

  res.render('login')

})
app.get('/register',function(req,res){
  res.render('register')

})
app.get("/secrets",function(req,res){
User.find({"secret":{$ne:null}},function(err,foundUser){
  if (err){
    console.log(err)
  }else {
    if (foundUser){
      res.render('secrets',{
        userFoundSecret:foundUser
      })
    }
  }
})
})
app.get('/submit',function(req,res){
  if (req.isAuthenticated()){
    res.render("submit")
  }else {
    res.redirect('/login')
  }
})
app.post('/submit',function(req,res){
  const secret=req.body.secret
  console.log(req.user.id)
  User.findById(req.user.id,function(err,foundUser){
    if (err){
      console.log(err)
    }else {
      if (foundUser){
        foundUser.secret=secret
        foundUser.save(function(){
          res.redirect('/secrets')
        })
      }
    }
  })
})
app.post('/register',function(req,res){
  User.register({username:req.body.username, active:true},req.body.password,function(err,user){
    if (err){
      res.redirect('/register')
    }
    else {
      passport.authenticate('local')(req,res,function(){
        res.redirect('/secrets')
      })
    }
  })

  });
app.post('/login',function(req,res){
  
const user=new User({
  username:req.body.username,
  password:req.body.password
})
req.login(user,function(err){
  if(err){
    console.log(err)
  }
  else {
    passport.authenticate('local')(req,res,function(){
      res.redirect('/secrets')
    })
  }
})
})
app.get( '/logout',function(req,res){
  req.logout(function(err){
    if (err){
      console.log(err)
    }
    else {
      res.redirect('/')
    }
  });

})


app.listen(process.env.PORT||3000,function(){
  console.log("Server started at port no 3000")
})
