const mongoose = require("mongoose");
const dbUrl = process.env.CONNECTION;

(async () => {
  try {
    await mongoose.connect(dbUrl, {
      useUnifiedTopology: true,
      useNewUrlParser: true,
    });
    console.log("mongodb connected successfully, message from connection.js");
  } catch (error) {
    console.log(` connection.js  ${error} `);
  }
})();
// mongoose.connect(dbUrl);
