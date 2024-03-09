require("dotenv").config();
const express = require("express");
const productsRouter = require("./routes/products");
const userRouter = require("./routes/user");
const app = express();
const PORT = process.env.PORT;
const cokkieParser = require("cookie-parser");
require("./connection/connection");


try {
  //middleware
  app.use(express.json());
  app.use(cokkieParser());

  //router //always in last  before listen server
  app.use("/api/v1",productsRouter);
  app.use("/api/v1",userRouter);
  app.listen(PORT, (req, res) => {
    console.log(`server start at http://localhost:${PORT}`);
  });
} catch (error) {
  console.log(error);
}
