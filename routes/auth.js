const router = require('express').Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const Joi = require('@hapi/joi');
const jwt = require('jsonwebtoken'); //

// para validar registro de usuario
const schemaRegister = Joi.object({
    name: Joi.string().min(6).max(255).required(),
    email: Joi.string().min(6).max(255).required().email(),
    password: Joi.string().min(6).max(1024).required()
})

// para validar inicio de sesión de usuario
const schemaLogin = Joi.object({
    email: Joi.string().min(6).max(255).required().email(),
    password: Joi.string().min(6).max(1024).required()
})

router.post('/login', async (req, res) => {
    // validaciones
    const { error } = schemaLogin.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });
    
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).json({ error: 'Credenciales incorrectas' });

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Credenciales incorrectas' });
     
    // Se crea el token
      const token = jwt.sign({
       name: user.name,
       id: user._id
      }, process.env.TOKEN_SECRET);

      res.header('auth-token', token).json({
        error: null,
        data: {token}
    });
});

router.post('/register', async (req, res) => {

  // Validaciones de usuario
    
     const {error} =  schemaRegister.validate(req.body);

      if(error){
         return  res.status(400).json(
             {error: error.details[0].message});
      }
   // Validar email unico
     const isEmailExist = await User.findOne({ email: req.body.email });
       if (isEmailExist) {
       return res.status(400).json(
           {error: 'Email ya registrado'});
   }
   //  Se encripta la contraseña
     const saltos = await bcrypt.genSalt(10);
     const password = await bcrypt.hash(req.body.password, saltos);


    const user =  new User({
        name:  req.body.name,
        email: req.body.email,
        password: password // en este caso que las propiedad y la const son iguales bastaria dejar solo la propiedad sin los :
    });
    try {
        const userDB = await user.save();
        res.json({
            error: null,
            data: userDB
        });
    } catch (error) {
        res.status(400).json(error);
    }
    
});

module.exports = router;