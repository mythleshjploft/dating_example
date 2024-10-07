const { Router } = require('express');
const router = Router();
const userController = require('./controllers/userController');

router.get('/', (req, res) => {
    res.send('Server Successfully Running.');
});
// User
router.post('/add_user', userController.addUser);
router.post('/login', userController.login);
module.exports = router;