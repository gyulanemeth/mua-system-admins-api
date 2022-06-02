import { list, readOne, updateOne, deleteOne } from 'mongoose-crudl'
import jwt from 'jsonwebtoken';
import AdminModel from '../models/Admin.js'
import MethodNotAllowedError from '../errors/MethodNotAllowedError.js';
import allowAccessTo from '../helpers/allowAccessTo.js'
import crypto from 'crypto';

export default (apiServer) => {
  const secrets =  process.env.SECRETS.split(' ');

  apiServer.get('/v1/admins/', async req => {
    try {
          allowAccessTo(req, secrets, [{ type: 'admin' }]);
          const response = await list(AdminModel)
          response.result.map(user => {
            if (!user.password) { // if user didn't have password that means he still didn't accept the invitation
              user.invitedtionStatus = "didn't accept yet";
            }
            return user
          })
          return response
        }catch (e) {
          console.log(e)
        }
  })

  apiServer.get('/v1/admins/:id', async req => {
    try {
        allowAccessTo(req, secrets, [{ type: 'admin' }]);
        const response = await readOne(AdminModel, { id: req.params.id });
        return response
      }catch (e) {
          console.log(e);
      }
  })

  apiServer.delete('/v1/admins/:id', async req => {
    try{
        allowAccessTo(req, secrets, [{ type: 'admin' }]);
        var adminCount = await AdminModel.count({});
        if(adminCount == 1){
          throw new MethodNotAllowedError(' Removeing the last admin is not allowed');
        }
        const response = await deleteOne(AdminModel, { id: req.params.id });
        return response
    }catch(e){
      console.log(e);
    }
  })

  apiServer.get('/v1/admins/:id/access-token', async req => {
    try{
    //  allowAccessTo(req, secrets, [{ type: 'admin', user:{req.params.id}},{type:"admin-login", user:{req.params.id}}]);
      const response = await readOne(AdminModel, { id: req.params.id })
      const payload = {
          type:"admin",
          user:{
            _id:response.result._id,
            email:response.result.email
          }
        }
      const token = jwt.sign(payload,secrets[0]);
      return {
        status:200,
        result:{
        accessToken:"Bearer " + token
      }
    }
    }catch(e){
      console.log(e);
    }
  })

  apiServer.put('/v1/admins/:id/name', async req => {
    try {
      allowAccessTo(req, secrets, [{ type: 'admin', user:{id:req.params.id}}]);

      const response = await updateOne(AdminModel, { id: req.params.id }, req.body);
      console.log(response)
      return response;
    } catch (e) {
      console.log(e);
    }
  })


  apiServer.put('/v1/admins/:id/password', async req => {
    try {
      allowAccessTo(req, secrets, [{ type: 'admin', user:{id:req.params.id}}]);
      const response = await readOne(AdminModel, { id: req.params.id, password:req.body.oldPassword});
      if(response.result._id && req.body.newPassword === req.body.newPasswordAgain){
        const hash = crypto.createHash('md5').update(req.body.newPassword).digest('hex')
        const response = await updateOne(AdminModel, { id: req.params.id},{password:hash});
        return response;
      }
    } catch (e) {
      console.log(e);
    }
  })
}
