const path = require('path');
const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router(path.join(__dirname, 'db.json'));
const middlewares = jsonServer.defaults();
const JWT = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const getAuthenticatedUser = users => (email, password) =>
  users.find(user => user.email === email && user.password === password);

const SECRET_KEY = 'zxcasdqwe098765';
const expiresIn = '24h';

const createToken = payload => JWT.sign(payload, SECRET_KEY, { expiresIn });

const verifyToken = token =>
  JWT.verify(token, SECRET_KEY, (err, decode) => ({
    err,
    decode,
  }));

server.use(middlewares);
server.use(jsonServer.bodyParser);

server.post('/auth/login', (req, res) => {
  const { users } = router.db.value();
  const { email, password } = req.body;
  const authenticatedUser = getAuthenticatedUser(users)(email, password);
  if (!authenticatedUser) {
    const status = 401;
    const message = 'Wrong user/password';
    return res.status(status).json({ status, message });
  }
  const accessToken = createToken({
    userId: authenticatedUser.id,
  });
  return res.status(201).json({ ...authenticatedUser, accessToken });
});

server.use(/^\/api/, (req, res, next) => {
  if (req.method === 'GET') {
    return next();
  }
  try {
    const [bearer, token] = (req.get('authorization') || '').split(' ');
    const { err, decode } = verifyToken(token);
    if (err) {
      throw err;
    }
    req.body.id = uuidv4();
    req.body.userId = decode.userId;
    req.body.createdAt = new Date();
    return next();
  } catch (err) {
    const status = 401;
    const message = 'Not authenticated';
    return res.status(status).json({ status, message });
  }
});

// Check if user already likes tweet
server.post(/tweets\/(.+)\/likes$/, (req, res, next) => {
  try {
    const { likes } = router.db.value();
    const likeExists = likes.some(
      l => l.tweetId === req.params[0] && l.userId === req.body.userId,
    );
    if (likeExists) {
      throw err;
    }
    return next();
  } catch (err) {
    const status = 400;
    const message = 'Not valid data';
    return res.status(status).json({ status, message });
  }
});

// Check if user is the owner of the like
server.delete(/likes\/(.+)$/, (req, res, next) => {
  try {
    const { likes } = router.db.value();
    const like = likes.find(l => l.id === req.params[0]);
    if (like && like.userId !== req.body.userId) {
      throw err;
    }
    return next();
  } catch (err) {
    const status = 401;
    const message = 'Not authorized';
    return res.status(status).json({ status, message });
  }
});

server.use('/api/v1/', router);

server.listen(3001, () => {
  console.log('JSON Server is running');
});
