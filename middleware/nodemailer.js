const nodeMailer = require("nodemailer");
exports.sendMail = async (email, subject, link) => {
   
  //create mailer transport
  const transport = nodeMailer.createTransport({
    service: "gmail",
    auth: {
      user: "sangwansachin631@gmail.com",
      pass: "bjktgxpsielhnfmy",
    },
  });
  //create mailer option
  const mailerOption ={
    from: "sangwansachin631@gmail.com",
    to: email,
    subject: subject,
    text: link,
  };
  //send mail
  transport.sendMail(mailerOption, (err, info) => {
    if (err) {
      console.log(err);
    } else {
      console.log(info);
    }
  });
};

