var express = require('express');
var router = express.Router();
const argon2 = require('argon2');
var QRCode = require('qrcode');
const c=require('constants');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');
const _sodium = require('libsodium-wrappers');
var multer  = require('multer')
var upload = multer({ dest: 'uploads/' })
var mongo = require('mongodb');
// Connection URI
const uri =
  "mongodb://localhost:27017/actseg?poolSize=20&w=majority";
// Create a new MongoClient
const client = new mongo.MongoClient(uri,{useUnifiedTopology: true});
const Speakeasy = require("speakeasy");


////////////////////////////////////
/////  PAGINA PRINCIPAL
///////////////////////////////////

router.get('/', async function(req, res, next) {
  if(req.session.uid && req.session.auth){
    await client.connect();
    const database = client.db("actseg");
    const collection = database.collection("users");
    var o_id = new mongo.ObjectID(req.session.uid);
    const userQuery = { _id: o_id};
    let user = await collection.findOne(userQuery);
    user.lastlogindate= new Date(user.lastlogin).toISOString();
    return res.render("index",{user})
  }
  return res.redirect("/login")
});

router.post('/', async function(req, res, next) {
  await client.connect();
  const database = client.db("actseg");
  const collection = database.collection("users");
  var o_id = new mongo.ObjectID(req.session.uid);
  const userQuery = { _id: o_id};
  let user = await collection.findOne(userQuery);
  console.log(user);
  if(!req.body.name){
    msg="ingresa el nombre"
    return  res.redirect("/");
  }
  user.name = req.body.name;
  await collection.save(user);
  user.lastlogindate= new Date(user.lastlogin).toISOString();
  return  res.render("index",{user,msg});
});

////////////////////////////////////
/////  LOGIN / REGISTRO
///////////////////////////////////

router.get('/login', function(req, res, next) {
  res.render('login');
});

router.post('/login', async function(req, res, next) {
  msg=null;
  if(!req.body.username || !req.body.password){
    msg="Faltan datos";
    return res.render('login',{msg});
  }
  await client.connect();
  const database = client.db("actseg");
  const collection = database.collection("users");
  const userQuery = { username: req.body.username };

  let user = await collection.findOne(userQuery);

  if(!user){
    msg="Datos incorrectos";
    return res.render('login',{msg});
  }
  const hashedPw =  user.password;
  let valid =  await argon2.verify(hashedPw,req.body.password)
  if(!valid){
    msg="Datos incorrectos";
    return res.render('login',{msg});
  }
  else{
    req.session.uid=user._id;
    if(user["otp-key"]==""){
      res.redirect("/2fa-setup")
    }
    else{
      res.redirect("/2fa")
    }
  }
});


router.get('/register', function(req, res, next) {
  res.render('register');
});

router.post('/register', async function(req, res, next) {
  msg=null;
  if(!req.body.username || !req.body.password || !req.body.name){
    msg="Faltan datos";
  }
  else{
    await client.connect();
    const database = client.db("actseg");
    const collection = database.collection("users");
    const userQuery = { username: req.body.username };

    let user = await collection.findOne(userQuery);

    if(user){
      msg="El usuario ya existe";
    }
    else{
      const hashedPw = await argon2.hash(req.body.password);
      let newUser = {
          "username":req.body.username,
          "password":hashedPw,
          "name":req.body.name,
          "lastlogin":0, 
          "otp-key":""
      }
      const result = await collection.insertOne(newUser);
      if(result.insertedCount==1){
       msg="Usuario registrado" 
      }
    }
  }
  res.render('register',{msg});
});

router.get('/logout', function(req, res, next) {
  req.session.destroy();
  res.redirect('/login');
});

////////////////////////////////////
/////  AUTENTICACION MULTIFACTOR
///////////////////////////////////

//////// LOGIN CON 2FA 

router.get('/2fa', async function(req, res, next) {
  if(!req.session.uid){
    return res.redirect("/login");
  }
  res.render("2fa-login");
});

router.post('/2fa', async function(req, res, next) {
  if(!req.session.uid){
    return res.redirect("/login");
  }
  if(!req.body.otp){
    msg="ingresa el codigo"
    return  res.render("2fa-login",{msg});
  }
  if(req.body.otp.length != 6){
    msg="el codigo debe ser de 6 digitos"
    return  res.render("2fa-login",{msg});
  }
  await client.connect();
    const database = client.db("actseg");
    const collection = database.collection("users");
    const log = database.collection("log");
    var o_id = new mongo.ObjectID(req.session.uid);
    const userQuery = { _id: o_id};
    let user = await collection.findOne(userQuery);
  let otpkey = user["otp-key"];
    let validcode =  Speakeasy.totp.verify({
      secret: otpkey,
      encoding: "base32",
      token: req.body.otp,
      window: 0
    });
    if(validcode){
      req.session.auth = true;
      user.lastlogin = Date.now();
      let logentry={
        "ip":req.ip,
        "uid":req.session.uid,
        "username":user.username,
        "date":user.lastlogin,
      }
      log.insertOne(logentry);
      await collection.save(user);
      return res.redirect("/");
    }
    else{
      console.log("OK")
      msg="codigo invalido"
      return  res.render("2fa-login",{msg});
    }
});
//////// ALTA DE CLAVE

router.get('/2fa-setup', async function(req, res, next) {
  if(!req.session.uid){
    res.redirect("/login");
  }
  else{
   genCode(req,res);
  }
});

let genCode = async (req,res)=>{
  let secret = Speakeasy.generateSecret({ name:"Proyecto final",length: 20 });
  req.session.otpkey = secret.base32;
  let uri = secret.otpauth_url;
  let qr = await QRCode.toDataURL(uri);
  return res.render('2fa-setup',{msg,qr});
}

router.post('/2fa-setup', async function(req, res, next) {
  if(!req.session.uid){
    return res.redirect("/login");
  }
  if(!req.body.otp){
    msg="ingresa el codigo"
    return genCode(req,res);
  }
  if(req.body.otp.length != 6){
    msg="el codigo debe ser de 6 digitos"
    return genCode(req,res);
  }
  let otpkey = req.session.otpkey;
    let validcode =  Speakeasy.totp.verify({
      secret: otpkey,
      encoding: "base32",
      token: req.body.otp,
      window: 0
    });
    if(validcode){
      const database = client.db("actseg");
      const collection = database.collection("users");
      var o_id = new mongo.ObjectID(req.session.uid);
      const userQuery = { _id: o_id};
      let user = await collection.findOne(userQuery);
      req.session.auth=true;
      user["otp-key"]=req.session.otpkey
      req.session.otpkey = null;

      await collection.save(user);
      return res.redirect("/");
    }
    else{
      msg="codigo invalido"
      return genCode(req,res);
    }
});


////////////////////////////////////
/////  BITACORA
///////////////////////////////////

router.get('/logs', async function(req, res, next) {
  if(!req.session.uid && req.session.auth){
    return res.redirect("/login");
  }
  await client.connect();
  const database = client.db("actseg");
  const collection = database.collection("log");
  let cursor = await collection.find();
  let logs = await cursor.toArray();
  res.render("logs",{logs})
});

////////////////////////////////////
/////  CIFRADO
///////////////////////////////////

let  hexdump = (buf) => {
  return buf.toString('hex');
}

///////// Descifrado de archivo
let processFileDecrypt = async (req,file, res) => {
  await _sodium.ready;
  const sodium = _sodium;
  let messages=[];
  console.log(req.body);
  let key="";
  try {
     key=sodium.from_hex(req.body.key); 
  } catch (e) {
    messages.push('Clave invalida')
    console.log(err); 
    return res.render('crypt',{messages}) 
  }
  let fileBuffer= await fs.readFile(file.path);
  let header_len=sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
  let header = Uint8Array.prototype.slice.call(fileBuffer,0,header_len);
  let encryptedContent = Uint8Array.prototype.slice.call(fileBuffer,header_len);
  let state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  let result = sodium.crypto_secretstream_xchacha20poly1305_pull(state, encryptedContent);
  console.log(result);
  if(result){
    let newFilename=file.originalname.substring(0, file.originalname.length - 8);
    let fileId=uuidv4();
    let fileDir=`${__dirname}/../public/files/${fileId}`;
    let filenameOut=`${__dirname}/../public/files/${fileId}/${newFilename}`;
    let downloadlink=`/files/${fileId}/${newFilename}`;
    try{
      await  fs.mkdir(fileDir,{recursive:true});
      await  fs.writeFile(filenameOut,result.message,{flag:"wx"});
      res.render('crypt',{messages,downloadlink})
    }
    catch(e){
      messages.push('Error al guardar archivo cifrado')
      console.log(err); 

      res.render('crypt',{messages}) 
    }
  }   
  else{
    messages.push('Clave invalida')
    console.log(err); 
    return res.render('crypt',{messages}) 
  }
}

///////// Cifrado

let processFileEncrypt = async (file, res) => {
  await _sodium.ready;
  const sodium = _sodium;
  let messages=[];
  let key = sodium.crypto_secretstream_xchacha20poly1305_keygen();
  messages.push("Clave Privada: "+hexdump(Buffer.from(key)));
  let init = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  let [state, header] = [init.state, init.header];
  let fileBuffer= await fs.readFile(file.path);
  let encryptedContent = sodium.crypto_secretstream_xchacha20poly1305_push(state,fileBuffer, null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

  var fileContent = new Uint8Array(header.length + encryptedContent.length);
  fileContent.set(header);
  fileContent.set(encryptedContent, header.length);
  let fileId=uuidv4();
  let fileDir=`${__dirname}/../public/files/${fileId}`;
  let filenameOut=`${__dirname}/../public/files/${fileId}/${file.originalname}.cifrado`;
  let downloadlink=`/files/${fileId}/${file.originalname}.cifrado`;
  try{
    await  fs.mkdir(fileDir,{recursive:true});
    await  fs.writeFile(filenameOut,fileContent,{flag:"wx"});
    res.render('crypt',{messages,downloadlink})
  }
  catch(e){
    messages.push('Error al guardar archivo cifrado')
    console.log(err); 

    res.render('crypt',{messages}) 
  }
}
///////// Vista
router.get('/crypt', function(req, res, next) {
  if(!req.session.uid && req.session.auth){
    return res.redirect("/login");
  }
  res.render('crypt');
});

///////// Procesamiento de formulario
router.post('/crypt', upload.single("doc"),function(req, res, next) {
  if(!req.session.uid && req.session.auth){
    return res.redirect("/login");
  }
  let error=null;
  if(!req.file) {
    error="No se subio un archivo";
  }
  else{
    if(req.body.submit=="Cifrar"){
      return processFileEncrypt(req.file,res);
    }
    else{
      if(!req.body.key) {
        error="No se ingreso clave privada";
      }
      else{
        return processFileDecrypt(req,req.file,res);
      }
    }
  }
  if(error){
    res.render('crypt',{error}); 
  }
  else{
    res.render('crypt'); 
  }
});

////////////////////////////////////
/////  FIRMA
///////////////////////////////////

let verifyFile = async (req,file, res) => {
  await _sodium.ready;
  const sodium = _sodium;
  let messages=[];
  console.log(req.body);
  let key="";
  try {
     key=sodium.from_hex(req.body.key); 
  } catch (e) {
    messages.push('Clave invalida')
    console.log(err); 
    return res.render('sign',{messages}) 
  }
  let fileBuffer= await fs.readFile(file.path);
  let result=null;
  try{
     result = sodium.crypto_sign_open(fileBuffer,key);
  }
  catch(e){
    messages.push('Clave invalida')
    console.log(e); 
    return res.render('sign',{messages}) 
  }
  if(result){
    let newFilename=file.originalname.substring(0, file.originalname.length - 8);
    let fileId=uuidv4();
    let fileDir=`${__dirname}/../public/files/${fileId}`;
    let filenameOut=`${__dirname}/../public/files/${fileId}/${newFilename}`;
    let downloadlink=`/files/${fileId}/${newFilename}`;
    try{
      await  fs.mkdir(fileDir,{recursive:true});
      await  fs.writeFile(filenameOut,result,{flag:"wx"});
      res.render('sign',{messages,downloadlink})
    }
    catch(e){
      messages.push('Error al guardar archivo cifrado')
      console.log(err); 

      res.render('sign',{messages}) 
    }
  }   
  else{
    messages.push('Clave invalida')
    console.log(err); 
    return res.render('sign',{messages}) 
  }
}

let signFile = async (file, res) => {
  await _sodium.ready;
  const sodium = _sodium;
  let messages=[];

  let keyPair=sodium.crypto_sign_keypair();
  let pubKey=Buffer.from(keyPair.publicKey);
  let privKey=Buffer.from(keyPair.privateKey);
  messages.push("Clave Publica: "+hexdump(pubKey));
  messages.push("Clave Privada: "+hexdump(privKey));
 
  let fileBuffer= await fs.readFile(file.path);
  messages.push("Longitud del archivo "+file.size+" bytes");
  let signedFileBuffer=Buffer.from(sodium.crypto_sign(fileBuffer,privKey));
  if(signedFileBuffer){
    let fileId=uuidv4();
    let fileDir=`${__dirname}/../public/files/${fileId}`;
    let filenameOut=`${__dirname}/../public/files/${fileId}/${file.originalname}.firmado`;
    let downloadlink=`/files/${fileId}/${file.originalname}.firmado`;
    try{
      await  fs.mkdir(fileDir,{recursive:true});
      await  fs.writeFile(filenameOut,signedFileBuffer,{flag:"wx"});
      res.render('sign',{messages,downloadlink})
    }
    catch(e){
      messages.push('Error al guardar archivo firmado')
      console.log(err); 

      res.render('sign',{messages}) 
    }
  } 
  
  res.render('sign',{messages})
}
router.get('/sign', function(req, res, next) {
  res.render('sign');
});

router.post('/sign', upload.single("doc"), function(req, res, next) {
  let error=null;
  if(!req.file) {
    error="No se subio un archivo";
  }
  else{
    if(req.body.submit=="Firmar"){
      return signFile(req.file,res);
    }
    else{
      if(!req.body.key) {
        error="No se ingreso clave publica";
      }
      else{
        return verifyFile(req,req.file,res);
      }
    }
  }
  if(error){
    res.render('sign',{error}); 
  }
  else{
    res.render('sign'); 
  }
});

module.exports = router;