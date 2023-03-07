const nodemailer = require('nodemailer');

exports.sendMail = async(options) => {
    // 1- create the transporter(transporter hiyye metel machine bten2elna l email taba3na mnel lnodejs server la 3end luser ma7all ma houwwe mawjoud)
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASSWORD
        }
    });

    // 2- DEFINE the mail options:
    const mailOptions = {
        from: "Elie Hannouch <mentor@techlarious.com>",
        to: options.email,
        subject: options.subject,
        text: options.message
    }

    // 3-send the mail
    await transporter.sendMail(mailOptions);

}