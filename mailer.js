const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendVerificationCode(email, code) {
  await transporter.sendMail({
    from: `"Аукционная система" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Код подтверждения регистрации',
    html: `
      <div style="max-width:500px; margin:0 auto; font-family:Arial;">
        <h2>Добро пожаловать в Аукционную систему!</h2>
        <p>Ваш код подтверждения:</p>
        <h1 style="color:#c9a96e; font-size:32px; letter-spacing:5px;">${code}</h1>
        <p>Введите этот код на сайте для завершения регистрации.</p>
        <hr>
        <p style="color:#888; font-size:12px;">Если вы не регистрировались, проигнорируйте это письмо.</p>
      </div>
    `
  });
}

module.exports = { sendVerificationCode };