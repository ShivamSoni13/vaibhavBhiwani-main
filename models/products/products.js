const mongoose = require("mongoose");
const userModel = require("../registerUser/registerUser");

const schema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "pleaser Enter name"],
  },
  price: {
    type: Number,
    required: [true, "please enter price of the products"],
    max: [100000, "length of the price not should be more then 5 charchter"],
  },
  ratings: {
    type: Number,
    default: 0,
  },
  noOfReviews: {
    type: Number,
    default: 0,
  },
  reviews: [
    {
      name: {
        type: String,
        required: [
          true,
          "User who provide review must have to enter there name ",
        ],
      },
      user: {
        type: mongoose.Schema.ObjectId,
        ref: "registerUserSchema",
      },
      rating: {
        type: Number,
        default: 0,
      },
      Comment: {
        type: String,
      },
    },
  ],

  images: [
    {
      public_id: {
        type: String,
        required: [true, "please enter cloudnary id of the images"],
      },
      url: {
        type: String,
        required: [true, "please enter  the url of the images"],
      },
    },
  ],

  category: {
    type: String,
    required: [true, "please enter category of the products"],
  },
  stock: {
    type: Number,
    required: [true, "please enter number of stock of the products"],
    maxLength: 5,
    default: 1,
  },

  user: {
    type: mongoose.Schema.ObjectId,
    ref: "registerUserSchema",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const ProductModel = new mongoose.model("products", schema);
module.exports = ProductModel;
