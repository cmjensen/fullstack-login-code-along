require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

//session settings
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7}
  })
);

massive({
  connectionString: CONNECTION_STRING,
  ssl: { rejectUnauthorized: false }
  }).then(db => {
  app.set('db', db)
  console.log('db connected');
});

app.post('/auth/signup', async ( req, res ) => {
  const { email, password } = req.body
  //allows us to use our database
  let db = req.app.get('db')
  const user = await db.check_user_exists(email)
  //db requests return an array, so we are checking the first item in the array (the email) against our db to see if that email is already associated with an account
  if( user[0] ){
    return res.status(401).send('User already exists')
  } 
  //if the email is not associated with an account, then we want to create one and add it to our db. never add a plain text pass to db. let's use salt and hash on the password before adding it to our db.
  let salt = bcrypt.genSaltSync(10)
  let hash = bcrypt.hashSync( password, salt )
  //below we are destructuring createdUser (it's an array and there will only be one object in the array so we will always want the index of 0. we can destructure it to avoid having to write createdUser[0].id and createdUser[0].email)
  let [createdUser] = await db.create_user( email, hash )
  //now let's keep this user information stored on the session on the server so that we will have it when the user comes back and we see their cookie.
  //req.session is a big empty object so we can store whatever we want on it.
  //a common use is to create a .user property (key, value pair) on the session that is equal to an object where we hold our user information
  req.session.user = { id: createdUser.id, email: createdUser. email }
  //sending the session information back to our front-end (notice the hashed pass is intentionally omitted here, but it is included in the user property on the session)
  res.status(200).send(req.session.user)
})

app.post('/auth/login', async ( req, res ) => {
  const { email, password } = req.body
  let db = req.app.get('db')
  const [user] = await db.check_user_exists(email)
  if ( !user ){
    return res.status(401).send('Incorrect login credentials. Please try again.')
  }
  //comparing the password from req.body (that the user just input, it's plain text) with the password on our server
  let authenticated = bcrypt.compareSync( password, user.user_password)
  //if the login credentials are correct, put them on that user's session (which is an object)
  if( authenticated ){
    req.session.user = {
      id: user.id,
      email: user.email
    }
  } else {
    return res.status(401).send('Incorrect login credentials. Please try again.')
  }
})

app.get('/auth/logout', async ( req, res ) => {
  req.session.destroy()
  res.sendStatus(200)
})

app.get('auth/user', ( req, res ) => {
  //check if there's a user on session
  if( req.session.user ) {
    res.status(200).send( req.session.user )
  } else {
    res.status(401).send('Please log in')
  }
})

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
