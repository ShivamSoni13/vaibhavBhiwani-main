// const { json } = require("express");

class apiFeatures{
    constructor(query,queryString){
        this.query=query;
        this.queryString=queryString;
    }
    search(){
        const keyWord = this.queryString.keyWord ?{
            name:{
                $regex:this.queryString.keyWord,
                $options:"i"
            }
        }:{}
        // console.log(keyWord);
        this.query=this.query.find({...keyWord});
        // console.log(this);
        return this;
    }
    filter(){
        const queryCopy={...this.queryString};
        console.log(queryCopy)
        const removeSomeFields=["keyWord","limit","page"];
        removeSomeFields.forEach(key=>delete queryCopy[key]);

        //filter for price and rating
        console.log(queryCopy);
        let queryString=JSON.stringify(queryCopy);
        queryString=queryString.replace(/\b(gt|gte|lt|lte)\b/g,(key)=>`$${key}`)
        

        this.query=this.query.find(JSON.parse(queryString));

        console.log(this);
        return this;
        

    }
}

module.exports=apiFeatures;