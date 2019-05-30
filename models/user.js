const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');

const userSchema = new Schema({
    email: {
        type: String,
        unique: true,
        lowercase: true
    },
    password: String
});

userSchema.pre('save', function(next) {
    const user = this;
    const salt = bcrypt.genSaltSync(10);
    bcrypt.hash(user.password, salt, function(err, hash) {
        if (err) { return next(err); }
        user.password = hash;
        next();
    });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
    const user = this;
    bcrypt.compare(candidatePassword, user.password, function(err, isMatch) {
        if (err) { return callback(err); }
        callback(null, isMatch);
    });
}

module.exports = mongoose.model('user', userSchema);
