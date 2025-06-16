const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const multer = require('multer');
const fs = require('fs');
const mime = require('mime-types');
const ffmpeg = require('fluent-ffmpeg');
const ffmpegPath = require('ffmpeg-static');
const ffprobePath = require('ffprobe-static').path;
const { execSync } = require('child_process');


// Configurar paths de FFmpeg
ffmpeg.setFfmpegPath(ffmpegPath);
ffmpeg.setFfprobePath(ffprobePath);

const PORT = 3000;
const JWT_SECRET = 'tu_secreto_jwt';

require('dotenv').config();

process.env.JWT_SECRET = 'tu_secreto_jwt';
process.env.DB_HOST = 'localhost';
process.env.DB_USER = 'root';
process.env.DB_PASSWORD = 'root';
process.env.DB_NAME = 'audio_app_db';
process.env.EMAIL_USER = 'l20212715@tectijuana.edu.mx';
process.env.EMAIL_PASS = 'wigc yuqk bkoi whnz';

// ====== CONFIGURACIÓN DE MULTER ======
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const signalsDir = path.join(__dirname, 'signals');
    if (!fs.existsSync(signalsDir)) {
      fs.mkdirSync(signalsDir, { recursive: true });
    }
    cb(null, signalsDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    cb(null, `audio-${uniqueSuffix}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['audio/mpeg', 'audio/wav', 'audio/x-wav', 'audio/aac'];
  const mimetype = mime.lookup(file.originalname);
  if (allowedTypes.includes(mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Tipo de archivo no permitido. Solo MP3, WAV, AAC'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 50 * 1024 * 1024
  }
});

// ====== MYSQL POOL CONFIG ======
console.log('✅ Conectado correctamente a la base de datos');
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'audio_app_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ====== CORREO CONFIG ======
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// ====== MIDDLEWARE GLOBAL ======
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/signals', express.static(path.join(__dirname, 'signals')));

const saltRounds = 10;

// ====== UTILIDADES ======
function generateRecoveryCode() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}
// Agrega esta función JUSTO AQUÍ (antes de verifyTokenMiddleware)
function ensureDirectoryExists(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}
function verifyTokenMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ success: false, message: 'Token no proporcionado' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Token inválido o expirado' });
  }
}

// Función para analizar audio con FFmpeg
async function analyzeAudio(filePath) {
  return new Promise((resolve, reject) => {
    ffmpeg.ffprobe(filePath, (err, metadata) => {
      if (err) return reject(err);
      
      const audioStream = metadata.streams.find(stream => stream.codec_type === 'audio');
      if (!audioStream) return reject(new Error('No se encontró stream de audio'));
      
      const audioInfo = {
        duration: metadata.format.duration,
        format: metadata.format.format_name,
        bitRate: metadata.format.bit_rate,
        sampleRate: audioStream.sample_rate,
        channels: audioStream.channels,
        codec: audioStream.codec_name
      };
      
      resolve(audioInfo);
    });
  });
}

// ====== MANEJO DE ERRORES GLOBALES ======
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ success: false, message: err.message });
  }
  res.status(500).json({ success: false, message: 'Error interno del servidor' });
});

// ====== ENDPOINTS ======

// TEST CONEXIÓN
app.get('/api/test', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 + 1 AS solution');
    res.json({ success: true, message: 'Conexión OK', dbStatus: rows[0].solution === 2 ? 'OK' : 'Error' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error con la base de datos' });
  }
});

// REGISTRO DE USUARIO
app.post('/api/register', async (req, res) => {
  const { nombre_completo, correo_electronico, contrasena } = req.body;

  if (!nombre_completo || !correo_electronico || !contrasena) {
    return res.status(400).json({ success: false, message: 'Todos los campos son requeridos' });
  }

  try {
    const [users] = await pool.query('SELECT * FROM usuarios WHERE correo_electronico = ?', [correo_electronico]);
    if (users.length > 0) {
      return res.status(400).json({ success: false, message: 'Correo ya registrado' });
    }

    const hashedPassword = await bcrypt.hash(contrasena, saltRounds);
    await pool.query(
      'INSERT INTO usuarios (nombre_completo, correo_electronico, contrasena, fecha_registro) VALUES (?, ?, ?, NOW())',
      [nombre_completo, correo_electronico, hashedPassword]
    );

    res.json({ success: true, message: 'Usuario registrado correctamente' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error en el registro' });
  }
});

// LOGIN DE USUARIO
app.post('/api/login', async (req, res) => {
  const { correo_electronico, contrasena } = req.body;

  if (!correo_electronico || !contrasena) {
    return res.status(400).json({ success: false, message: 'Faltan credenciales' });
  }

  try {
    const [users] = await pool.query('SELECT * FROM usuarios WHERE correo_electronico = ?', [correo_electronico]);

    if (users.length === 0 || !(await bcrypt.compare(contrasena, users[0].contrasena))) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    const user = users[0];
    await pool.query('UPDATE usuarios SET ultimo_acceso = NOW() WHERE id_usuario = ?', [user.id_usuario]);

    const token = jwt.sign({ id: user.id_usuario, email: user.correo_electronico }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      success: true,
      message: 'Inicio de sesión exitoso',
      token,
      userData: {
        id: user.id_usuario,
        nombre: user.nombre_completo,
        email: user.correo_electronico
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error en el servidor' });
  }
});

// SOLICITAR CÓDIGO DE RECUPERACIÓN
app.post('/api/request-reset-code', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: 'El correo electrónico es requerido' });
  }

  try {
    const [users] = await pool.query('SELECT id_usuario FROM usuarios WHERE correo_electronico = ?', [email]);

    const recoveryCode = crypto.randomBytes(6).toString('hex').toUpperCase();
    const expirationTime = new Date(Date.now() + 15 * 60 * 1000);

    if (users.length > 0) {
      await pool.query(
        'UPDATE usuarios SET token_recuperacion = ?, token_expiracion = ? WHERE correo_electronico = ?',
        [recoveryCode, expirationTime, email]
      );

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Código de recuperación de contraseña',
        text: `Tu código de recuperación es: ${recoveryCode}\n\nEste código expirará en 15 minutos.`,
        html: `<p>Tu código de recuperación es: <strong>${recoveryCode}</strong></p><p>Este código expirará en 15 minutos.</p>`
      };

      await transporter.sendMail(mailOptions);
    }

    return res.json({ success: true, message: 'Si el correo existe, recibirás un código de recuperación' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error al procesar la solicitud' });
  }
});

// VERIFICAR CÓDIGO
app.post('/api/verify-recovery-code', async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ success: false, message: 'Email y código son requeridos' });
  }

  try {
    const [users] = await pool.query(
      'SELECT * FROM usuarios WHERE correo_electronico = ? AND token_recuperacion = ? AND token_expiracion > NOW()',
      [email, code]
    );

    if (users.length === 0) {
      return res.status(400).json({ success: false, message: 'Código inválido o expirado' });
    }

    res.json({ success: true, message: 'Código verificado correctamente' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error interno del servidor' });
  }
});

// RESTABLECER CONTRASEÑA
app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
      return res.status(400).json({ success: false, message: 'Todos los campos son requeridos' });
    }

    const [users] = await pool.query(
      'SELECT * FROM usuarios WHERE correo_electronico = ? AND token_recuperacion = ? AND token_expiracion > NOW()',
      [email, code]
    );

    if (users.length === 0) {
      return res.status(400).json({ success: false, message: 'Código inválido o expirado' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    await pool.query(
      'UPDATE usuarios SET contrasena = ?, token_recuperacion = NULL, token_expiracion = NULL WHERE correo_electronico = ?',
      [hashedPassword, email]
    );

    res.json({ success: true, message: 'Contraseña actualizada exitosamente' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error interno del servidor' });
  }
});

app.post('/api/subir-audio', upload.single('audio'), verifyTokenMiddleware, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Archivo no proporcionado' });
    }

    const id_usuario = req.user.id;
    const nombre_original = req.file.originalname;
    const nombre_sistema = `audio_${Date.now()}_${Math.floor(Math.random() * 1000)}${path.extname(nombre_original)}`;
    const ruta_almacenamiento = path.join('signals', nombre_sistema);
    const tamano_bytes = req.file.size;
    const fecha_actual = new Date();

    // 1. Insertar en archivos_mp3
    const [resultArchivo] = await pool.query(
      'INSERT INTO archivos_mp3 (id_usuario, nombre_original, nombre_sistema, ruta_almacenamiento, tamano_bytes, fecha_subida, fecha_modificacion, estado) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [id_usuario, nombre_original, nombre_sistema, ruta_almacenamiento, tamano_bytes, fecha_actual, fecha_actual, 'subido']
    );

    const id_archivo = resultArchivo.insertId;

    // 2. REGISTRAR EN HISTORIAL (ESTO ES LO QUE FALTABA)
    await pool.query(
      'INSERT INTO historial_archivos (id_usuario, id_archivo, accion, fecha_accion, detalles) VALUES (?, ?, ?, NOW(), ?)',
      [id_usuario, id_archivo, 'subida', `Subió el archivo: ${nombre_original}`]
    );

    // 3. Mover el archivo
    const newPath = path.join(path.dirname(req.file.path), nombre_sistema);
    fs.renameSync(req.file.path, newPath);
    
    res.json({
      success: true,
      message: 'Audio subido y registrado en historial',
      fileInfo: {
        id: id_archivo,
        originalName: nombre_original,
        systemName: nombre_sistema,
        path: ruta_almacenamiento,
        size: tamano_bytes,
        uploadDate: fecha_actual
      }
    });
  } catch (error) {
    console.error('Error al subir audio:', error);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ success: false, message: 'Error al subir audio' });
  }
});

// ANALIZAR AUDIO Y EXTRAER MUESTRAS REALES (VERSIÓN SIN ALMACENAMIENTO LOCAL)
app.post('/api/analizar-audio', upload.single('audio'), verifyTokenMiddleware, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Archivo no proporcionado' });
    }

    // Asegurar que el directorio temporal exista
    const tempDir = path.join(__dirname, 'temp');
    ensureDirectoryExists(tempDir); // Ahora la función está definida

    // 1. Analizar el audio con FFmpeg para obtener metadatos
    const audioAnalysis = await analyzeAudio(req.file.path);
    
    // 2. Preparar nombres de archivos temporales únicos
    const timestamp = Date.now();
    const tempFile = path.join(tempDir, `${timestamp}_samples.raw`);
    const logFile = path.join(tempDir, `${timestamp}_ffmpeg.log`);
    
    try {
      // Comando FFmpeg para extraer muestras
      const command = `"${ffmpegPath}" -y -i "${req.file.path}" ` +
                     `-ac 1 -ar 1000 -acodec pcm_f32le -f f32le "${tempFile}" ` +
                     `2> "${logFile}"`;
      
      console.log(`Ejecutando comando: ${command}`);
      execSync(command, { stdio: 'inherit' });
      
      // Verificar que el archivo de muestras existe
      if (!fs.existsSync(tempFile)) {
        const logContent = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf-8') : 'No hay registro';
        throw new Error(`FFmpeg no generó el archivo de muestras. Log:\n${logContent}`);
      }

      // Leer el archivo de muestras binarias
      const fileStats = fs.statSync(tempFile);
      if (fileStats.size === 0) {
        throw new Error('El archivo de muestras está vacío');
      }

      const rawData = fs.readFileSync(tempFile);
      const sampleCount = rawData.length / Float32Array.BYTES_PER_ELEMENT;
      const samples = new Float32Array(rawData.buffer, rawData.byteOffset, sampleCount);
      
      // Normalizar muestras
      const maxSample = Math.max(...samples.map(Math.abs));
      const normalizedSamples = Array.from(samples).map(s => s / (maxSample || 1));
      
      // Limpiar archivos temporales
      fs.unlinkSync(tempFile);
      if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);

      res.json({
        success: true,
        message: 'Audio analizado exitosamente',
        audioAnalysis: {
          duration: audioAnalysis.duration,
          sampleRate: 1000,
          originalSampleRate: audioAnalysis.sampleRate,
          filename: req.file.originalname,
          fonocardiogramData: normalizedSamples
        }
      });
    } catch (error) {
      console.error('Error al procesar audio:', error);
      
      // Limpieza en caso de error
      if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
      if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      
      res.status(500).json({ 
        success: false, 
        message: 'Error al procesar las muestras de audio',
        error: error.message
      });
    }
  } catch (error) {
    console.error('Error al analizar audio:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error interno al analizar audio',
      error: error.message
    });
  }
}); 
//historial de audios 
app.get('/api/historial-audios', verifyTokenMiddleware, async (req, res) => {
  let userId;
  
  try {
    userId = req.user.id;

    // 1. Verificar usuario
    const [user] = await pool.query(
      'SELECT id_usuario FROM usuarios WHERE id_usuario = ? AND cuenta_activa = 1', 
      [userId]
    );
    
    if (user.length === 0) {
      return res.status(403).json({ 
        success: false, 
        message: 'Cuenta inactiva o no autorizada' 
      });
    }

    // 2. Obtener todos los registros del historial
    const [audios] = await pool.query(
      `SELECT 
         h.id_historial AS id,
         COALESCE(a.nombre_original, 'Archivo sin nombre') AS name,
         DATE_FORMAT(h.fecha_accion, '%d/%m/%Y %H:%i') AS formatted_date,
         h.fecha_accion AS raw_date,
         COALESCE(a.ruta_almacenamiento, '') AS path,
         COALESCE(a.tamano_bytes, 0) AS size,
         COALESCE(a.duracion_segundos, 0) AS duration,
         h.accion AS action,
         h.detalles AS description
       FROM historial_archivos h
       LEFT JOIN archivos_mp3 a ON h.id_archivo = a.id_archivo
       WHERE h.id_usuario = ?
       ORDER BY h.fecha_accion DESC
       LIMIT 100`,
      [userId]
    );

    // 3. Filtrar en Node.js (no en MySQL) los archivos que existen físicamente
    const validAudios = await Promise.all(
      audios.map(async (audio) => {
        if (!audio.path) return null;
        
        try {
          const fullPath = path.join(__dirname, audio.path);
          const exists = fs.existsSync(fullPath);
          return exists ? audio : null;
        } catch (error) {
          console.error(`Error verificando archivo ${audio.path}:`, error);
          return null;
        }
      })
    );

    // 4. Eliminar nulos y transformar datos
    const filteredAudios = validAudios.filter(audio => audio !== null);
    const result = filteredAudios.map(audio => ({
      id: audio.id,
      name: audio.name,
      date: audio.formatted_date,
      rawDate: audio.raw_date,
      path: audio.path,
      size: audio.size,
      duration: audio.duration,
      action: audio.action,
      description: audio.description,
      downloadUrl: audio.path ? `${process.env.BASE_URL}${audio.path}` : null
    }));

    console.log(`[Historial] Usuario ${userId} - ${result.length}/${audios.length} audios válidos`);

    res.json({ 
      success: true,
      count: result.length,
      audios: result,
      metadata: {
        totalInDB: audios.length,
        totalValidFiles: result.length
      }
    });
  } catch (error) {
    console.error('[Error Historial]', {
      userId: userId, 
      error: error.message,
      stack: error.stack
    });
    
    res.status(500).json({ 
      success: false, 
      message: 'Error al obtener historial',
      debug: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});
// ====== INICIAR SERVIDOR ======
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});