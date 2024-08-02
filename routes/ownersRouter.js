const express = require('express');
const router= express.Router();
const ownerModel= require('../models/owner-model');


if(process.env.NODE_ENV === "development"){
    router.post("/create", async function(req, res) {
        let owners = await ownerModel.find();
        if(owners.length > 0){
            return res
              .status(503)
              .send("You dont have permission to create");
        } 

        let {fullname, email, password} = req.body;

        let createdOwner= await ownerModel.create({
            fullname,
            email,
            password
        });

        res.status(201).send(createdOwner);
    });
}

router.get("/admin", function(req, res){
    let success= req.flash("success")
    res.render("createproducts", {success, contact: false, footer:false});
})

router.get("/admin2", function(req, res){
    let success= req.flash("success")
    res.render("admin2", {success, contact: false, footer:false});
})

router.get("/allproducts", function(req, res){
    res.render("admin", { contact: false});
})


module.exports = router;