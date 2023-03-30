const{ response } = require("express");
const bcrypt = require("bcryptjs/dist/bcrypt");

const Usuario = require("../models/usuario");
const { generarJWT } =require('../helpers/jwt')

const crearUsuario = async ( req, res = response) => {
    
    const { email,password} = req.body;

    try {
        const existeEmail = await Usuario.findOne({email});
        if (existeEmail) {
            return res.status(400).json({
                ok:false,
                msg:'El correo ya a sido registrado'
            })
        }
        const usuario = new Usuario( req.body );
        //?Encriptar password
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync(password,salt);
        await usuario.save();
        //?generar jsonweb token
        const token = await generarJWT( usuario.id);
        res.json({
            ok:true,
            usuario,
            token
        });

    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok:false,
            msg:'Hable con el admin'
        });
    }
}
const login = async ( req, res = response) => {
    const { email,password} = req.body;
    try {
        const usuaruioBD = await Usuario.findOne({email});
        if (!usuaruioBD) {
            return res.status(400).json({
                ok:false,
                msg:'El correo no existe'
            });
        }
        const passwordValido = bcrypt.compareSync(password, usuaruioBD.password);
        if (!passwordValido) {
            return res.status(400).json({
                ok:false,
                msg:'El password no es valido'
            });
        }
        const token = await generarJWT(usuaruioBD.id)
        res.json({
            ok:true,
            usuario: usuaruioBD,
            token
        });
        
    } catch (error) {
       return  res.status(500).json({
            ok:false,
            msg:'Hable con el admin',
        });
    }

}

const renewToken = async (req, res = response)=>{
   const uid = req.uid;
   const token = await generarJWT(uid);
   const usuario = await Usuario.findById(uid);

    res.json({
        ok:true,
        usuario,
        token
    });
}

module.exports= {
    crearUsuario,
    login,
    renewToken
}