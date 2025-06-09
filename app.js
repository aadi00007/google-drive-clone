const express= require('express')
const app = express();
const userRouter= require('./routes/user.routes');

app.use(express.urlencoded({extended:true}));

app.use('/user', userRouter)


app.set('view engine', 'ejs');
app.listen(3000,()=>{
    console.log('server is running on port 3000')
})