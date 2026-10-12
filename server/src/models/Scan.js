import mongoose from 'mongoose';
const schema = new mongoose.Schema({type:{type:String,required:true},input:{type:String,default:''},result:{type:mongoose.Schema.Types.Mixed,required:true}},{timestamps:true});
export default mongoose.models.Scan || mongoose.model('Scan',schema);
